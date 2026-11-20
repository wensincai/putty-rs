//! `pt-gui` — graphical front end (egui) for the PuTTY→Rust rewrite.
//!
//! Counterpart of PuTTY's `unix/window.c` (GTK) and `windows/window.c` (Win32).
//! Rendering is a character grid owned by `pt-term`; the SSH session runs on a
//! tokio runtime and talks to the UI through channels, so the UI never blocks
//! on network I/O.

#![forbid(unsafe_code)]

mod creds;

use eframe::egui;
use pt_core::config::{Config, SessionProfile};
use pt_core::shell::{run_shell, InputMsg, ShellChunk, ShellOptions};
use pt_core::ConnectOptions;
use pt_term::{Cell, Color, Screen};
use std::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::mpsc::unbounded_channel;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 640.0])
            .with_min_inner_size([640.0, 400.0])
            .with_title("pt — SSH client (PuTTY rewrite)"),
        ..Default::default()
    };
    eframe::run_native("pt-gui", options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}

/// Events from an SSH task to the UI thread, tagged with the owning tab.
enum UiEvent {
    Output { tab: u64, data: Vec<u8> },
    Connected { tab: u64, fingerprint: String },
    Closed { tab: u64, status: Option<u32> },
    Failed { tab: u64, message: String },
}

struct Session {
    screen: Screen,
    input: tokio::sync::mpsc::UnboundedSender<InputMsg>,
    connected: bool,
    error: Option<String>,
    scroll: usize,
    selection: Option<((usize, usize), (usize, usize))>,
    drag_anchor: Option<(usize, usize)>,
    fingerprint: String,
    /// Target whose password came from the OS credential store, so a rejected
    /// secret can be dropped and the user asked for a fresh one.
    stored_pw_target: Option<String>,
}

/// One terminal tab: a live (or failing) SSH session and its UI state.
/// The counterpart of one PuTTY window.
struct Tab {
    id: u64,
    /// Shown on the tab strip; `user@host[:port]` captured at connect time.
    title: String,
    status: String,
    session: Option<Session>,
}

struct Form {
    name: String,
    host: String,
    port: u16,
    user: String,
    key: String,
    proxy: String,
    password: String,
    cols: u16,
    rows: u16,
    edit_index: Option<usize>,
}

impl Default for Form {
    fn default() -> Self {
        Form {
            name: String::new(),
            host: String::new(),
            port: 22,
            user: std::env::var("USERNAME")
                .or_else(|_| std::env::var("USER"))
                .unwrap_or_default(),
            key: String::new(),
            proxy: String::new(),
            password: String::new(),
            cols: 80,
            rows: 24,
            edit_index: None,
        }
    }
}

struct App {
    cfg: Config,
    /// Open terminal tabs; several sessions can run at the same time.
    tabs: Vec<Tab>,
    /// Currently shown tab, if any.
    active_tab: Option<u64>,
    next_tab_id: u64,
    rt: tokio::runtime::Runtime,
    evt_tx: Sender<UiEvent>,
    evt_rx: Receiver<UiEvent>,
    form: Form,
    show_form: bool,
    /// Global notices (config save failures, …) not tied to a tab.
    status: String,
    theme_dark: bool,
    /// A saved session waiting for its password before connecting.
    pw_dialog: Option<PwDialog>,
    /// Target of the session whose password was read from the credential
    /// store for the current connection attempt.
    stored_pw_target: Option<String>,
}

/// Password asked at connect time; only persisted to the OS credential store
/// when the user ticks "Remember password".
struct PwDialog {
    profile: SessionProfile,
    text: String,
    remember: bool,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut style = (*cc.egui_ctx.style()).clone();
        style.visuals = egui::Visuals::dark();
        cc.egui_ctx.set_style(style);
        let cfg = Config::load().unwrap_or_default();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("tokio runtime");
        let (evt_tx, evt_rx) = channel();
        App {
            cfg,
            tabs: Vec::new(),
            active_tab: None,
            next_tab_id: 1,
            rt,
            evt_tx,
            evt_rx,
            form: Form::default(),
            show_form: false,
            status: String::new(),
            theme_dark: true,
            pw_dialog: None,
            stored_pw_target: None,
        }
    }

    fn tab_mut(&mut self, id: u64) -> Option<&mut Tab> {
        self.tabs.iter_mut().find(|t| t.id == id)
    }

    /// Close a tab: tell the shell we are leaving (Eof), drop it, and focus
    /// the nearest remaining tab.
    fn close_tab(&mut self, id: u64) {
        if let Some(t) = self.tabs.iter().find(|t| t.id == id) {
            if let Some(s) = &t.session {
                let _ = s.input.send(InputMsg::Eof);
            }
        }
        self.tabs.retain(|t| t.id != id);
        if self.active_tab == Some(id) {
            self.active_tab = self.tabs.last().map(|t| t.id);
        }
    }

    /// Connect straight away when a key is configured or a remembered password
    /// exists in the OS credential store; otherwise ask for one.
    fn start_connect(&mut self, profile: SessionProfile, ctx: egui::Context) {
        if profile.auth.key_path.is_some() {
            self.connect(profile, None, ctx);
        } else if let Some(pw) = creds::get(&profile.target()) {
            self.connect_stored(profile, pw, ctx);
        } else {
            self.pw_dialog = Some(PwDialog {
                profile,
                text: String::new(),
                remember: true,
            });
        }
    }

    /// Like [`App::start_connect`], but with a password typed into the session
    /// form (used by "Save & connect"); empty means ask in the dialog. A typed
    /// password is remembered in the credential store — that is what users
    /// expect "Save & connect" to do.
    fn start_connect_with(&mut self, profile: SessionProfile, pw: String, ctx: egui::Context) {
        if pw.is_empty() {
            self.start_connect(profile, ctx);
        } else {
            if let Err(e) = creds::set(&profile.target(), &pw) {
                self.status = format!("cannot remember password: {e}");
            }
            self.connect(profile, Some(pw), ctx);
        }
    }

    fn connect_stored(&mut self, profile: SessionProfile, pw: String, ctx: egui::Context) {
        self.stored_pw_target = Some(profile.target());
        self.connect(profile, Some(pw), ctx);
    }

    fn connect(&mut self, profile: SessionProfile, password: Option<String>, ctx: egui::Context) {
        let cols = profile.terminal.cols;
        let rows = profile.terminal.rows;
        let (itx, irx) = unbounded_channel::<InputMsg>();
        let id = self.next_tab_id;
        self.next_tab_id += 1;
        self.tabs.push(Tab {
            id,
            title: profile.target(),
            status: format!("connecting to {}…", profile.target()),
            session: Some(Session {
                screen: Screen::new(cols, rows, profile.terminal.scrollback),
                input: itx,
                connected: false,
                error: None,
                scroll: 0,
                selection: None,
                drag_anchor: None,
                fingerprint: String::new(),
                stored_pw_target: self.stored_pw_target.take(),
            }),
        });
        self.active_tab = Some(id);

        let evt = self.evt_tx.clone();
        let ctx2 = ctx.clone();
        let term = profile.terminal.term.clone();
        self.rt.spawn(async move {
            let mut opts = ConnectOptions::new(profile);
            opts.password = password;
            let result = async {
                let connected = pt_core::connect(opts).await?;
                let _ = evt.send(UiEvent::Connected {
                    tab: id,
                    fingerprint: connected.host_key.fingerprint.clone(),
                });
                ctx2.request_repaint();
                let handle = std::sync::Arc::new(connected.handle);
                let shell_opts = ShellOptions {
                    term,
                    cols: cols.max(1),
                    rows: rows.max(1),
                    want_pty: true,
                };
                let evt_out = evt.clone();
                let ctx_out = ctx2.clone();
                run_shell(&handle, &shell_opts, irx, move |chunk| {
                    let bytes = match chunk {
                        ShellChunk::Stdout(d) | ShellChunk::Stderr(d) => d,
                    };
                    let _ = evt_out.send(UiEvent::Output { tab: id, data: bytes });
                    ctx_out.request_repaint();
                })
                .await
            }
            .await;
            match result {
                Ok(status) => {
                    let _ = evt.send(UiEvent::Closed { tab: id, status });
                }
                Err(e) => {
                    let _ = evt.send(UiEvent::Failed { tab: id, message: e.to_string() });
                }
            }
            ctx2.request_repaint();
        });
    }

    fn drain_events(&mut self) {
        while let Ok(ev) = self.evt_rx.try_recv() {
            match ev {
                UiEvent::Output { tab, data } => {
                    if let Some(t) = self.tab_mut(tab) {
                        if let Some(s) = &mut t.session {
                            s.screen.feed(&data);
                            for r in s.screen.take_responses() {
                                let _ = s.input.send(InputMsg::Data(r));
                            }
                        }
                    }
                }
                UiEvent::Connected { tab, fingerprint } => {
                    if let Some(t) = self.tab_mut(tab) {
                        t.status = format!("connected ({fingerprint})");
                        if let Some(s) = &mut t.session {
                            s.connected = true;
                            s.fingerprint = fingerprint;
                        }
                    }
                }
                UiEvent::Closed { tab, status } => {
                    if let Some(t) = self.tab_mut(tab) {
                        t.status = match status {
                            Some(c) => format!("session closed (status {c})"),
                            None => "session closed".into(),
                        };
                        if let Some(s) = &mut t.session {
                            s.connected = false;
                        }
                    }
                }
                UiEvent::Failed { tab, message } => {
                    let Some(t) = self.tab_mut(tab) else {
                        continue; // tab already closed by the user
                    };
                    if let Some(s) = &mut t.session {
                        s.connected = false;
                        s.error = Some(message.clone());
                        // A remembered password that the server rejected is
                        // now stale: drop it so the next ▶ asks for a fresh
                        // one instead of silently failing forever.
                        if let Some(target) = s.stored_pw_target.take() {
                            creds::delete(&target);
                            t.status = format!(
                                "error: {message} — the remembered password was rejected and cleared; click ▶ to re-enter"
                            );
                        } else {
                            t.status = format!("error: {message}");
                        }
                    } else {
                        t.status = format!("error: {message}");
                    }
                }
            }
        }
    }

    fn save_form(&mut self) {
        let f = &self.form;
        if f.host.trim().is_empty() {
            self.status = "host is required".into();
            return;
        }
        let mut p = self
            .form
            .edit_index
            .and_then(|i| self.cfg.sessions.get(i).cloned())
            .unwrap_or_else(|| SessionProfile::new("", &f.host, &f.user));
        p.name = if f.name.trim().is_empty() {
            format!("{}@{}", f.user, f.host)
        } else {
            f.name.clone()
        };
        p.host = f.host.trim().to_string();
        p.port = f.port;
        p.user = f.user.trim().to_string();
        p.auth.key_path = if f.key.trim().is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(f.key.trim()))
        };
        p.proxy = if f.proxy.trim().is_empty() {
            None
        } else {
            pt_core::ProxyConfig::parse(f.proxy.trim()).ok()
        };
        p.terminal.cols = f.cols;
        p.terminal.rows = f.rows;
        // A non-empty password field means "remember this password" — for
        // both Save and Save & connect. Empty keeps whatever is stored.
        if !f.password.is_empty() {
            if let Err(e) = creds::set(&p.target(), &f.password) {
                self.status = format!("cannot remember password: {e}");
            }
        }
        match self.form.edit_index {
            Some(i) => self.cfg.sessions[i] = p,
            None => self.cfg.sessions.push(p),
        }
        if let Err(e) = self.cfg.save() {
            self.status = format!("cannot save sessions: {e}");
        }
        self.show_form = false;
    }
}

fn palette(idx: u8) -> egui::Color32 {
    // PuTTY's default 16 colours, then the xterm 256-colour cube.
    const ANSI: [(u8, u8, u8); 16] = [
        (0, 0, 0),
        (187, 0, 0),
        (0, 187, 0),
        (187, 187, 0),
        (0, 0, 187),
        (187, 0, 187),
        (0, 187, 187),
        (187, 187, 187),
        (85, 85, 85),
        (255, 85, 85),
        (85, 255, 85),
        (255, 255, 85),
        (85, 85, 255),
        (255, 85, 255),
        (85, 255, 255),
        (255, 255, 255),
    ];
    if idx < 16 {
        let (r, g, b) = ANSI[idx as usize];
        return egui::Color32::from_rgb(r, g, b);
    }
    if idx >= 232 {
        let v = 8 + (idx - 232) * 10;
        return egui::Color32::from_rgb(v, v, v);
    }
    let i = idx - 16;
    let r = i / 36;
    let g = (i % 36) / 6;
    let b = i % 6;
    let f = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
    egui::Color32::from_rgb(f(r), f(g), f(b))
}

fn color_of(c: Color, default: egui::Color32) -> egui::Color32 {
    match c {
        Color::Default => default,
        Color::Indexed(i) => palette(i),
        Color::Rgb(r, g, b) => egui::Color32::from_rgb(r, g, b),
    }
}

fn cell_colors(cell: &Cell) -> (egui::Color32, egui::Color32) {
    let mut fg = color_of(cell.attrs.fg, egui::Color32::from_rgb(204, 204, 204));
    let mut bg = color_of(cell.attrs.bg, egui::Color32::from_rgb(12, 12, 12));
    if cell.attrs.reverse {
        std::mem::swap(&mut fg, &mut bg);
    }
    if cell.attrs.bold {
        fg = fg.linear_multiply(1.25);
    }
    if cell.attrs.dim {
        fg = fg.linear_multiply(0.6);
    }
    (fg, bg)
}

/// Text as the remote shell expects: LF becomes CR (Enter sends CR), and when
/// the application enabled bracketed paste mode, wrap it so vim/readline treat
/// it as one blob instead of executing embedded newlines.
fn paste_bytes(text: &str, bracketed: bool) -> Vec<u8> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n").replace('\n', "\r");
    if bracketed {
        let mut b = b"\x1b[200~".to_vec();
        b.extend_from_slice(text.as_bytes());
        b.extend_from_slice(b"\x1b[201~");
        b
    } else {
        text.into_bytes()
    }
}

/// Read the OS clipboard; a fresh handle per call keeps it simple and safe.
fn clipboard_text() -> Option<String> {
    arboard::Clipboard::new().ok()?.get_text().ok().filter(|s| !s.is_empty())
}

/// Copy the current selection (if any) to the clipboard.
fn copy_selection(sess: &Session, ui: &egui::Ui) {
    let Some(((x0, y0), (x1, y1))) = sess.selection else {
        return;
    };
    let (ax, ay, bx, by) = if (y0, x0) <= (y1, x1) {
        (x0, y0, x1, y1)
    } else {
        (x1, y1, x0, y0)
    };
    let mut text = String::new();
    for y in ay..=by {
        let line = sess.screen.line(y);
        let s: String = line
            .iter()
            .skip(ax)
            .take(bx.saturating_sub(ax) + 1)
            .filter(|c| c.width != 0)
            .map(|c| c.ch)
            .collect();
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(s.trim_end());
    }
    ui.ctx().copy_text(text);
}

/// Map an egui key press to the byte sequence a terminal expects.
fn key_bytes(key: egui::Key, mods: egui::Modifiers, app_cursor: bool) -> Option<Vec<u8>> {
    use egui::Key::*;

    // ---- Ctrl combos → C0 controls --------------------------------------
    // Ctrl-A..Z are 0x01..0x1a; the classic aliases too:
    // Ctrl+[ = Esc, Ctrl+] = GS, Ctrl+\ = FS, Ctrl+2..8 (readline/vim habits).
    // AltGr shows up as ctrl+alt on Windows, so exclude alt from this arm.
    if mods.ctrl && !mods.alt {
        // Arrows with Ctrl fall through to the xterm modifier encoding.
        let c: Option<u8> = match key {
            A => Some(0x01),
            B => Some(0x02),
            C => Some(0x03),
            D => Some(0x04),
            E => Some(0x05),
            F => Some(0x06),
            G => Some(0x07),
            H => Some(0x08),
            I => Some(0x09),
            J => Some(0x0a),
            K => Some(0x0b),
            L => Some(0x0c),
            M => Some(0x0d),
            N => Some(0x0e),
            O => Some(0x0f),
            P => Some(0x10),
            Q => Some(0x11),
            R => Some(0x12),
            S => Some(0x13),
            T => Some(0x14),
            U => Some(0x15),
            V => Some(0x16),
            W => Some(0x17),
            X => Some(0x18),
            Y => Some(0x19),
            Z => Some(0x1a),
            Space => Some(0x00),
            Num2 => Some(0x00),
            Num3 => Some(0x1b),
            Num4 => Some(0x1c),
            Num5 => Some(0x1d),
            Num6 => Some(0x1e),
            Num7 => Some(0x1f),
            Num8 => Some(0x7f),
            OpenBracket => Some(0x1b),
            CloseBracket => Some(0x1d),
            Backslash => Some(0x1c),
            // Arrows with Ctrl fall through to the xterm modifier encoding.
            _ => None,
        };
        if let Some(c) = c {
            return Some(vec![c]);
        }
    }

    // ---- Tab / Shift+Tab -------------------------------------------------
    // Shift+Tab is backtab (CSI Z): menu completion in bash, visual mode jump.
    if key == Tab {
        return Some(if mods.shift {
            b"\x1b[Z".to_vec()
        } else {
            b"\t".to_vec()
        });
    }

    // ---- Arrows, with xterm modifier parameters --------------------------
    // Ctrl+Left/Right = word jump in readline ("1;5"); Alt+arrows likewise
    // ("1;3"). Plain arrows follow application cursor keypad mode.
    let dir: Option<char> = match key {
        ArrowUp => Some('A'),
        ArrowDown => Some('B'),
        ArrowRight => Some('C'),
        ArrowLeft => Some('D'),
        _ => None,
    };
    if let Some(c) = dir {
        if mods.alt || mods.ctrl {
            let param = match (mods.ctrl, mods.alt) {
                (true, true) => "1;7",
                (true, false) => "1;5",
                (false, true) => "1;3",
                (false, false) => unreachable!(),
            };
            return Some(format!("\x1b[{param}{c}").into_bytes());
        }
        return Some(if app_cursor {
            format!("\x1bO{c}").into_bytes()
        } else {
            format!("\x1b[{c}").into_bytes()
        });
    }

    // ---- Alt+Backspace → ESC DEL (kill word backwards in readline) -------
    if key == Backspace {
        return Some(if mods.alt {
            b"\x1b\x7f".to_vec()
        } else {
            vec![0x7f]
        });
    }

    let seq: Vec<u8> = match key {
        Enter => b"\r".to_vec(),
        Escape => vec![0x1b],
        Home => b"\x1b[H".to_vec(),
        End => b"\x1b[F".to_vec(),
        PageUp => b"\x1b[5~".to_vec(),
        PageDown => b"\x1b[6~".to_vec(),
        Insert => b"\x1b[2~".to_vec(),
        Delete => b"\x1b[3~".to_vec(),
        F1 => b"\x1bOP".to_vec(),
        F2 => b"\x1bOQ".to_vec(),
        F3 => b"\x1bOR".to_vec(),
        F4 => b"\x1bOS".to_vec(),
        F5 => b"\x1b[15~".to_vec(),
        F6 => b"\x1b[17~".to_vec(),
        F7 => b"\x1b[18~".to_vec(),
        F8 => b"\x1b[19~".to_vec(),
        F9 => b"\x1b[20~".to_vec(),
        F10 => b"\x1b[21~".to_vec(),
        F11 => b"\x1b[23~".to_vec(),
        F12 => b"\x1b[24~".to_vec(),
        _ => return None,
    };
    Some(seq)
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();
        let status = self
            .active_tab
            .and_then(|id| self.tabs.iter().find(|t| t.id == id))
            .map(|t| t.status.clone())
            .unwrap_or_else(|| self.status.clone());

        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("pt");
                ui.separator();
                if ui.button("New session…").clicked() {
                    self.form = Form::default();
                    self.show_form = true;
                }
                if ui
                    .add_enabled(self.active_tab.is_some(), egui::Button::new("Disconnect"))
                    .clicked()
                {
                    if let Some(id) = self.active_tab {
                        self.close_tab(id);
                    }
                }
                let mut dark = self.theme_dark;
                if ui.checkbox(&mut dark, "Dark").changed() {
                    self.theme_dark = dark;
                    let mut style = (*ctx.style()).clone();
                    style.visuals = if dark {
                        egui::Visuals::dark()
                    } else {
                        egui::Visuals::light()
                    };
                    ctx.set_style(style);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(&status);
                });
            });
        });

        // ---- tab strip: one tab per live session ----------------------------
        if !self.tabs.is_empty() {
            egui::TopBottomPanel::top("tabs")
                .frame(egui::Frame::new().inner_margin(egui::Margin::symmetric(6, 2)))
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        let mut close_id = None;
                        let mut select_id = None;
                        for t in &self.tabs {
                            let selected = self.active_tab == Some(t.id);
                            // Colour instead of a status glyph: egui's default
                            // fonts lack most dingbats (U+2715 ✕ renders as a
                            // tofu box), but colours are always available.
                            let color = if t
                                .session
                                .as_ref()
                                .is_some_and(|s| s.connected)
                            {
                                egui::Color32::from_rgb(140, 220, 140)
                            } else {
                                egui::Color32::from_rgb(235, 130, 120)
                            };
                            if ui
                                .selectable_label(
                                    selected,
                                    egui::RichText::new(&t.title).color(color),
                                )
                                .clicked()
                            {
                                select_id = Some(t.id);
                            }
                            // × (U+00D7) is the only cross glyph present in the
                            // bundled fonts; U+2715 ✕ is not.
                            if ui
                                .add(
                                    egui::Button::new(egui::RichText::new("×").weak())
                                        .frame(false)
                                        .small(),
                                )
                                .on_hover_text("close this tab")
                                .clicked()
                            {
                                close_id = Some(t.id);
                            }
                            ui.separator();
                        }
                        if let Some(id) = select_id {
                            self.active_tab = Some(id);
                        }
                        if let Some(id) = close_id {
                            self.close_tab(id);
                        }
                    });
                });
        }

        egui::SidePanel::left("sessions")
            .resizable(true)
            .default_width(200.0)
            .show(ctx, |ui| {
                ui.label(egui::RichText::new("Saved sessions").strong());
                ui.separator();
                let mut connect_idx = None;
                let mut edit_idx = None;
                let mut delete_idx = None;
                for (i, s) in self.cfg.sessions.iter().enumerate() {
                    ui.horizontal(|ui| {
                        if ui.small_button("▶").on_hover_text("connect").clicked() {
                            connect_idx = Some(i);
                        }
                        let label = if s.name.is_empty() {
                            s.target()
                        } else {
                            s.name.clone()
                        };
                        if ui.selectable_label(false, label).clicked() {
                            connect_idx = Some(i);
                        }
                        // ✎ (U+270E) is missing from the bundled fonts; ✏ (U+270F)
                        // is covered by emoji-icon-font.
                        if ui.small_button("✏").clicked() {
                            edit_idx = Some(i);
                        }
                        if ui.small_button("✖").clicked() {
                            delete_idx = Some(i);
                        }
                    });
                }
                if let Some(i) = connect_idx {
                    let profile = self.cfg.sessions[i].clone();
                    self.start_connect(profile, ctx.clone());
                }
                if let Some(i) = edit_idx {
                    let s = &self.cfg.sessions[i];
                    self.form = Form {
                        name: s.name.clone(),
                        host: s.host.clone(),
                        port: s.port,
                        user: s.user.clone(),
                        key: s
                            .auth
                            .key_path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default(),
                        proxy: s.proxy.as_ref().map(|p| p.label()).unwrap_or_default(),
                        password: String::new(),
                        cols: s.terminal.cols,
                        rows: s.terminal.rows,
                        edit_index: Some(i),
                    };
                    self.show_form = true;
                }
                if let Some(i) = delete_idx {
                    let t = self.cfg.sessions[i].target();
                    creds::delete(&t);
                    self.cfg.sessions.remove(i);
                    let _ = self.cfg.save();
                }
                ui.separator();
                ui.label(
                    egui::RichText::new(
                        "Click the terminal first so it has keyboard focus.\n\
                         Ctrl+Shift+C copies the selection.",
                    )
                    .small()
                    .weak(),
                );
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            let Some(idx) = self
                .active_tab
                .and_then(|id| self.tabs.iter().position(|t| t.id == id))
            else {
                ui.centered_and_justified(|ui| {
                    ui.label("No session. Use “New session…” or pick a saved one.");
                });
                return;
            };
            let font_size = self.cfg.defaults.terminal.font_size;
            let tab = &mut self.tabs[idx];
            match &mut tab.session {
                Some(sess) => draw_terminal(sess, font_size, ui),
                None => {
                    ui.centered_and_justified(|ui| {
                        ui.label(&tab.status);
                    });
                }
            }
        });

        if self.show_form {
            let mut open = self.show_form;
            egui::Window::new("Session")
                .open(&mut open)
                .default_width(430.0)
                .show(ctx, |ui| {
                    egui::Grid::new("form")
                        .num_columns(2)
                        .spacing([8.0, 6.0])
                        .show(ui, |ui| {
                            ui.label("Name");
                            ui.text_edit_singleline(&mut self.form.name);
                            ui.end_row();
                            ui.label("Host");
                            ui.text_edit_singleline(&mut self.form.host);
                            ui.end_row();
                            ui.label("Port");
                            ui.add(egui::DragValue::new(&mut self.form.port).range(1..=65535));
                            ui.end_row();
                            ui.label("User");
                            ui.text_edit_singleline(&mut self.form.user);
                            ui.end_row();
                            ui.label("Key file");
                            ui.text_edit_singleline(&mut self.form.key);
                            ui.end_row();
                            ui.label("Proxy");
                            ui.text_edit_singleline(&mut self.form.proxy);
                            ui.end_row();
                            ui.label("Password");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.form.password).password(true),
                            );
                            ui.end_row();
                            ui.label("Size");
                            ui.horizontal(|ui| {
                                ui.add(egui::DragValue::new(&mut self.form.cols).range(20..=400));
                                ui.label("×");
                                ui.add(egui::DragValue::new(&mut self.form.rows).range(5..=200));
                            });
                            ui.end_row();
                        });
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            self.save_form();
                        }
                        if ui.button("Save & connect").clicked() {
                            self.save_form();
                            if let Some(p) = self.cfg.sessions.last().cloned() {
                                let pw = std::mem::take(&mut self.form.password);
                                self.start_connect_with(p, pw, ctx.clone());
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            self.show_form = false;
                        }
                    });
                });
            self.show_form = open;
        }

        // Connect-time password dialog for saved sessions without a
        // remembered password. The password is only written to the OS
        // credential store (never to sessions.json) when "Remember" is ticked.
        if self.pw_dialog.is_some() {
            let mut open = true;
            let mut submit = false;
            let mut cancel = false;
            if let Some(d) = &mut self.pw_dialog {
                egui::Window::new(format!("Password — {}", d.profile.target()))
                    .open(&mut open)
                    .default_width(380.0)
                    .show(ctx, |ui| {
                        ui.label("Password (leave empty if the server accepts your key):");
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut d.text).password(true),
                        );
                        if resp.lost_focus()
                            && ui.input(|i| i.key_pressed(egui::Key::Enter))
                        {
                            submit = true;
                        }
                        ui.checkbox(&mut d.remember, "Remember password (Windows Credential Manager, encrypted)");
                        ui.separator();
                        ui.horizontal(|ui| {
                            if ui.button("Connect").clicked() {
                                submit = true;
                            }
                            if ui.button("Cancel").clicked() {
                                cancel = true;
                            }
                        });
                    });
                if cancel {
                    open = false;
                }
            }
            match self.pw_dialog.take() {
                Some(d) if submit => {
                    let pw = if d.text.is_empty() { None } else { Some(d.text) };
                    if let Some(p) = &pw {
                        if d.remember {
                            match creds::set(&d.profile.target(), p) {
                                Ok(()) => self.stored_pw_target = None,
                                Err(e) => {
                                    self.status = format!("cannot remember password: {e}");
                                }
                            }
                        }
                    }
                    self.connect(d.profile, pw, ctx.clone());
                }
                Some(d) if open => self.pw_dialog = Some(d),
                _ => {}
            }
        }
    }
}

/// Draw one session's terminal grid and route its input. A free function so
/// the borrow of the tab does not go through `App`.
fn draw_terminal(sess: &mut Session, font_size: f32, ui: &mut egui::Ui) {
    let font = egui::FontId::monospace(font_size);
        let (cw, ch) = {
            let g = ui
                .painter()
                .layout_no_wrap("M".to_owned(), font.clone(), egui::Color32::WHITE);
            (g.size().x.max(1.0), g.size().y.max(1.0))
        };
        let (cols, rows) = sess.screen.size();

        // Resize the emulator when the panel no longer fits the grid.
        let avail = ui.available_size();
        let fit_cols = ((avail.x / cw).floor() as usize).clamp(20, 400);
        let fit_rows = ((avail.y / ch).floor() as usize).clamp(5, 200);
        if fit_cols != cols || fit_rows != rows {
            sess.screen.resize(fit_cols as u16, fit_rows as u16);
            let _ = sess.input.send(InputMsg::Resize {
                cols: fit_cols as u16,
                rows: fit_rows as u16,
            });
        }
        let (cols, rows) = sess.screen.size();

        let (rect, resp) = ui.allocate_exact_size(
            egui::vec2(cols as f32 * cw, rows as f32 * ch),
            egui::Sense::click_and_drag(),
        );
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, egui::Color32::from_rgb(12, 12, 12));

        // scrollback offset: 0 = live screen
        let scroll = sess.scroll.min(sess.screen.scrollback_len());
        let total_rows = sess.screen.scrollback_len() + rows;
        let first = total_rows.saturating_sub(rows + scroll);
        for y in 0..rows {
            let abs = first + y;
            let line: &[Cell] = if abs < sess.screen.scrollback_len() {
                sess.screen.scrollback_line(abs).unwrap_or(&[])
            } else {
                sess.screen.line(abs - sess.screen.scrollback_len())
            };
            for (x, cell) in line.iter().enumerate().take(cols) {
                if cell.width == 0 {
                    continue; // right half of a wide char
                }
                let (fg, bg) = cell_colors(cell);
                let pos = egui::pos2(rect.left() + x as f32 * cw, rect.top() + y as f32 * ch);
                if bg != egui::Color32::from_rgb(12, 12, 12) {
                    painter.rect_filled(egui::Rect::from_min_size(pos, egui::vec2(cw, ch)), 0.0, bg);
                }
                if cell.ch != ' ' {
                    painter.text(
                        pos,
                        egui::Align2::LEFT_TOP,
                        cell.ch.to_string(),
                        font.clone(),
                        fg,
                    );
                }
            }
        }

        // selection highlight
        if let Some(((x0, y0), (x1, y1))) = sess.selection {
            let (ax, ay, bx, by) = if (y0, x0) <= (y1, x1) {
                (x0, y0, x1, y1)
            } else {
                (x1, y1, x0, y0)
            };
            for y in ay..=by {
                let start = if y == ay { ax } else { 0 };
                let end = if y == by { bx } else { cols - 1 };
                let r = egui::Rect::from_min_max(
                    egui::pos2(rect.left() + start as f32 * cw, rect.top() + y as f32 * ch),
                    egui::pos2(
                        rect.left() + (end + 1) as f32 * cw,
                        rect.top() + (y + 1) as f32 * ch,
                    ),
                );
                painter.rect_filled(r, 0.0, egui::Color32::from_rgba_unmultiplied(90, 140, 220, 90));
            }
        }

        // cursor
        if scroll == 0 && sess.screen.cursor().visible {
            let c = sess.screen.cursor();
            let pos = egui::pos2(rect.left() + c.col as f32 * cw, rect.top() + c.row as f32 * ch);
            painter.rect_filled(
                egui::Rect::from_min_size(pos, egui::vec2(cw, ch)),
                0.0,
                egui::Color32::from_rgba_unmultiplied(200, 200, 200, 110),
            );
        }

        // ---- input
        if resp.clicked() {
            resp.request_focus();
        }
        let focused = resp.has_focus();
        if focused {
            // egui reserves Tab (focus navigation), Escape (drop focus) and
            // the arrow keys (cardinal focus movement) for itself, which makes
            // a terminal useless: Tab never completes, and pressing Esc in vim
            // silently removes keyboard focus from the terminal widget. Lock
            // them to this widget — it is a terminal, they are terminal keys.
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(
                    resp.id,
                    egui::EventFilter {
                        tab: true,
                        escape: true,
                        horizontal_arrows: true,
                        vertical_arrows: true,
                    },
                );
            });
        }
        let app_cursor = sess.screen.modes().app_cursor_keys;
        let bracketed_paste = sess.screen.modes().bracketed_paste;
        let cur_mods = ui.input(|i| i.modifiers);
        let events = ui.input(|i| i.events.clone());
        for ev in events {
            match ev {
                egui::Event::Text(t) if focused => {
                    // Alt+char is the Meta prefix (Alt-b/Alt-f word jump in
                    // readline). AltGr reports ctrl+alt, so exclude it.
                    let bytes = if cur_mods.alt && !cur_mods.ctrl {
                        let mut b = vec![0x1b];
                        b.extend_from_slice(&t.into_bytes());
                        b
                    } else {
                        t.into_bytes()
                    };
                    let _ = sess.input.send(InputMsg::Data(bytes));
                }
                // IME commits (Chinese/Japanese/…) arrive here, not as Text.
                egui::Event::Ime(egui::ImeEvent::Commit(t)) if focused => {
                    let _ = sess.input.send(InputMsg::Data(t.into_bytes()));
                }
                egui::Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } if focused => {
                    if modifiers.ctrl && modifiers.shift {
                        if key == egui::Key::C {
                            copy_selection(sess, ui);
                        }
                        continue;
                    }
                    // Ctrl+V: egui only synthesizes Paste for Shift+Insert on
                    // Windows, so intercept Ctrl+V and paste ourselves.
                    if modifiers.ctrl && !modifiers.shift && key == egui::Key::V {
                        if let Some(text) = clipboard_text() {
                            let _ = sess
                                .input
                                .send(InputMsg::Data(paste_bytes(&text, bracketed_paste)));
                        }
                        continue;
                    }
                    // Shift+PageUp/PageDown: local scrollback, like PuTTY.
                    if modifiers.shift && !modifiers.ctrl {
                        match key {
                            egui::Key::PageUp => {
                                let max = sess.screen.scrollback_len() as i64;
                                sess.scroll =
                                    (sess.scroll as i64 + sess.screen.size().1 as i64).clamp(0, max)
                                        as usize;
                                continue;
                            }
                            egui::Key::PageDown => {
                                sess.scroll = sess
                                    .scroll
                                    .saturating_sub(sess.screen.size().1);
                                continue;
                            }
                            _ => {}
                        }
                    }
                    if let Some(bytes) = key_bytes(key, modifiers, app_cursor) {
                        let _ = sess.input.send(InputMsg::Data(bytes));
                    }
                }
                // Windows: Ctrl+Insert. Paste comes through on Shift+Insert.
                egui::Event::Copy if focused => copy_selection(sess, ui),
                egui::Event::Paste(s) if focused => {
                    let _ = sess
                        .input
                        .send(InputMsg::Data(paste_bytes(&s, bracketed_paste)));
                }
                _ => {}
            }
        }

        // ---- scrollback
        if resp.hovered() {
            let delta = ui.input(|i| i.raw_scroll_delta.y);
            if delta != 0.0 {
                let step = (delta / ch).round() as i64;
                let max = sess.screen.scrollback_len() as i64;
                sess.scroll = ((sess.scroll as i64 + step).clamp(0, max)) as usize;
            }
        }

        // ---- dragging selection
        if let Some(pos) = resp.interact_pointer_pos() {
            if resp.drag_started() || resp.clicked() {
                let x = ((pos.x - rect.left()) / cw).floor().max(0.0) as usize;
                let y = ((pos.y - rect.top()) / ch).floor().max(0.0) as usize;
                let cell = (x.min(cols - 1), y.min(rows - 1));
                sess.drag_anchor = Some(cell);
                sess.selection = Some((cell, cell));
            } else if resp.dragged() {
                if let Some(a) = sess.drag_anchor {
                    let x = ((pos.x - rect.left()) / cw).floor().max(0.0) as usize;
                    let y = ((pos.y - rect.top()) / ch).floor().max(0.0) as usize;
                    sess.selection = Some((a, (x.min(cols - 1), y.min(rows - 1))));
                }
            }
        }
        if resp.drag_stopped() {
            sess.drag_anchor = None;
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kb(k: egui::Key, mods: egui::Modifiers, app_cursor: bool) -> Option<Vec<u8>> {
        key_bytes(k, mods, app_cursor)
    }

    #[test]
    fn control_keys_map_to_c0() {
        assert_eq!(kb(egui::Key::C, mods_ctrl(), false).unwrap(), vec![0x03]); // Ctrl-C
        assert_eq!(kb(egui::Key::D, mods_ctrl(), false).unwrap(), vec![0x04]); // Ctrl-D
        assert_eq!(kb(egui::Key::Space, mods_ctrl(), false).unwrap(), vec![0x00]);
    }

    #[test]
    fn navigation_sequences() {
        let mods = egui::Modifiers::default();
        assert_eq!(kb(egui::Key::ArrowUp, mods, false).unwrap(), b"\x1b[A".to_vec());
        assert_eq!(kb(egui::Key::Delete, mods, false).unwrap(), b"\x1b[3~".to_vec());
        assert_eq!(kb(egui::Key::Enter, mods, false).unwrap(), b"\r".to_vec());
        assert_eq!(kb(egui::Key::Backspace, mods, false).unwrap(), vec![0x7f]);
        assert_eq!(kb(egui::Key::Escape, mods, false).unwrap(), vec![0x1b]);
    }

    #[test]
    fn modified_keys() {
        let mods = egui::Modifiers::default();
        // Shift+Tab is backtab, not tab.
        let shift = egui::Modifiers { shift: true, ..Default::default() };
        assert_eq!(kb(egui::Key::Tab, shift, false).unwrap(), b"\x1b[Z".to_vec());
        assert_eq!(kb(egui::Key::Tab, mods, false).unwrap(), b"\t".to_vec());
        // Ctrl+[ is ESC; Ctrl+] is GS; Ctrl+\ is FS.
        assert_eq!(kb(egui::Key::OpenBracket, mods_ctrl(), false).unwrap(), vec![0x1b]);
        assert_eq!(kb(egui::Key::CloseBracket, mods_ctrl(), false).unwrap(), vec![0x1d]);
        assert_eq!(kb(egui::Key::Backslash, mods_ctrl(), false).unwrap(), vec![0x1c]);
        // Modified arrows: Ctrl+Right = word jump, Alt+Up likewise.
        assert_eq!(
            kb(egui::Key::ArrowRight, mods_ctrl(), false).unwrap(),
            b"\x1b[1;5C".to_vec()
        );
        let alt = egui::Modifiers { alt: true, ..Default::default() };
        assert_eq!(
            kb(egui::Key::ArrowUp, alt, false).unwrap(),
            b"\x1b[1;3A".to_vec()
        );
        // Alt+Backspace = ESC DEL (kill word).
        assert_eq!(kb(egui::Key::Backspace, alt, false).unwrap(), b"\x1b\x7f".to_vec());
    }

    #[test]
    fn paste_wraps_in_bracketed_mode() {
        assert_eq!(paste_bytes("a\nb", false), b"a\rb".to_vec());
        assert_eq!(
            paste_bytes("a\nb", true),
            b"\x1b[200~a\rb\x1b[201~".to_vec()
        );
        assert_eq!(paste_bytes("x\r\ny", false), b"x\ry".to_vec());
    }

    fn mods_ctrl() -> egui::Modifiers {
        egui::Modifiers { ctrl: true, ..Default::default() }
    }

    #[test]
    fn app_cursor_mode_changes_arrows() {
        let mods = egui::Modifiers::default();
        assert_eq!(key_bytes(egui::Key::ArrowUp, mods, true).unwrap(), b"\x1bOA".to_vec());
    }

    #[test]
    fn palette_endpoints() {
        assert_eq!(palette(0), egui::Color32::from_rgb(0, 0, 0));
        assert_eq!(palette(15), egui::Color32::from_rgb(255, 255, 255));
        assert_eq!(palette(232), egui::Color32::from_rgb(8, 8, 8));
        assert_eq!(palette(255), egui::Color32::from_rgb(238, 238, 238));
    }
}
