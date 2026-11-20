//! `pt-gui` — graphical front end (egui) for the PuTTY→Rust rewrite.
//!
//! Counterpart of PuTTY's `unix/window.c` (GTK) and `windows/window.c` (Win32).
//! Rendering is a character grid owned by `pt-term`; the SSH session runs on a
//! tokio runtime and talks to the UI through channels, so the UI never blocks
//! on network I/O.

#![forbid(unsafe_code)]

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

/// Events from the SSH task to the UI thread.
enum UiEvent {
    Output(Vec<u8>),
    Connected(String),
    Closed(Option<u32>),
    Failed(String),
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
    session: Option<Session>,
    rt: tokio::runtime::Runtime,
    evt_tx: Sender<UiEvent>,
    evt_rx: Receiver<UiEvent>,
    form: Form,
    show_form: bool,
    status: String,
    theme_dark: bool,
    /// A saved session waiting for its password before connecting.
    pw_dialog: Option<PwDialog>,
}

/// Password asked at connect time; never persisted to sessions.json.
struct PwDialog {
    profile: SessionProfile,
    text: String,
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
            session: None,
            rt,
            evt_tx,
            evt_rx,
            form: Form::default(),
            show_form: false,
            status: String::new(),
            theme_dark: true,
            pw_dialog: None,
        }
    }

    /// Connect straight away when a key is configured; otherwise ask for a
    /// password first (the GUI cannot prompt mid-authentication like the CLI).
    fn start_connect(&mut self, profile: SessionProfile, ctx: egui::Context) {
        if profile.auth.key_path.is_some() {
            self.connect(profile, None, ctx);
        } else {
            self.pw_dialog = Some(PwDialog { profile, text: String::new() });
        }
    }

    /// Like [`App::start_connect`], but with a password typed into the session
    /// form (used by "Save & connect"); empty means ask in the dialog.
    fn start_connect_with(&mut self, profile: SessionProfile, pw: String, ctx: egui::Context) {
        if pw.is_empty() {
            self.start_connect(profile, ctx);
        } else {
            self.connect(profile, Some(pw), ctx);
        }
    }

    fn connect(&mut self, profile: SessionProfile, password: Option<String>, ctx: egui::Context) {
        let cols = profile.terminal.cols;
        let rows = profile.terminal.rows;
        let (itx, irx) = unbounded_channel::<InputMsg>();
        self.session = Some(Session {
            screen: Screen::new(cols, rows, profile.terminal.scrollback),
            input: itx,
            connected: false,
            error: None,
            scroll: 0,
            selection: None,
            drag_anchor: None,
            fingerprint: String::new(),
        });
        self.status = format!("connecting to {}…", profile.target());

        let evt = self.evt_tx.clone();
        let ctx2 = ctx.clone();
        let term = profile.terminal.term.clone();
        self.rt.spawn(async move {
            let mut opts = ConnectOptions::new(profile);
            opts.password = password;
            let result = async {
                let connected = pt_core::connect(opts).await?;
                let _ = evt.send(UiEvent::Connected(
                    connected.host_key.fingerprint.clone(),
                ));
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
                    let _ = evt_out.send(UiEvent::Output(bytes));
                    ctx_out.request_repaint();
                })
                .await
            }
            .await;
            match result {
                Ok(status) => {
                    let _ = evt.send(UiEvent::Closed(status));
                }
                Err(e) => {
                    let _ = evt.send(UiEvent::Failed(e.to_string()));
                }
            }
            ctx2.request_repaint();
        });
    }

    fn drain_events(&mut self) {
        while let Ok(ev) = self.evt_rx.try_recv() {
            match ev {
                UiEvent::Output(bytes) => {
                    if let Some(s) = &mut self.session {
                        s.screen.feed(&bytes);
                        for r in s.screen.take_responses() {
                            let _ = s.input.send(InputMsg::Data(r));
                        }
                    }
                }
                UiEvent::Connected(fp) => {
                    if let Some(s) = &mut self.session {
                        s.connected = true;
                        s.fingerprint = fp.clone();
                    }
                    self.status = format!("connected ({fp})");
                }
                UiEvent::Closed(status) => {
                    self.status = match status {
                        Some(c) => format!("session closed (status {c})"),
                        None => "session closed".into(),
                    };
                    if let Some(s) = &mut self.session {
                        s.connected = false;
                    }
                }
                UiEvent::Failed(msg) => {
                    self.status = format!("error: {msg}");
                    if let Some(s) = &mut self.session {
                        s.connected = false;
                        s.error = Some(msg);
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

/// Map an egui key press to the byte sequence a terminal expects.
fn key_bytes(key: egui::Key, mods: egui::Modifiers, app_cursor: bool) -> Option<Vec<u8>> {
    use egui::Key::*;
    if mods.ctrl {
        // Control characters: Ctrl-A..Ctrl-Z → 0x01..0x1a
        let c = match key {
            A => 0x01,
            B => 0x02,
            C => 0x03,
            D => 0x04,
            E => 0x05,
            F => 0x06,
            G => 0x07,
            H => 0x08,
            I => 0x09,
            J => 0x0a,
            K => 0x0b,
            L => 0x0c,
            M => 0x0d,
            N => 0x0e,
            O => 0x0f,
            P => 0x10,
            Q => 0x11,
            R => 0x12,
            S => 0x13,
            T => 0x14,
            U => 0x15,
            V => 0x16,
            W => 0x17,
            X => 0x18,
            Y => 0x19,
            Z => 0x1a,
            Space => 0x00,
            _ => return None,
        };
        return Some(vec![c]);
    }
    let seq: Vec<u8> = match key {
        Enter => b"\r".to_vec(),
        Backspace => vec![0x7f],
        Tab => b"\t".to_vec(),
        Escape => vec![0x1b],
        ArrowUp => {
            if app_cursor {
                b"\x1bOA".to_vec()
            } else {
                b"\x1b[A".to_vec()
            }
        }
        ArrowDown => {
            if app_cursor {
                b"\x1bOB".to_vec()
            } else {
                b"\x1b[B".to_vec()
            }
        }
        ArrowRight => {
            if app_cursor {
                b"\x1bOC".to_vec()
            } else {
                b"\x1b[C".to_vec()
            }
        }
        ArrowLeft => {
            if app_cursor {
                b"\x1bOD".to_vec()
            } else {
                b"\x1b[D".to_vec()
            }
        }
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

        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("pt");
                ui.separator();
                if ui.button("New session…").clicked() {
                    self.form = Form::default();
                    self.show_form = true;
                }
                if ui.button("Disconnect").clicked() {
                    if let Some(s) = &self.session {
                        let _ = s.input.send(InputMsg::Eof);
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
                    ui.label(&self.status);
                });
            });
        });

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
                        if ui.small_button("✎").clicked() {
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
            if self.session.is_none() {
                ui.centered_and_justified(|ui| {
                    ui.label("No session. Use “New session…” or pick a saved one.");
                });
                return;
            }
            self.draw_terminal(ui);
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

        // Connect-time password dialog for saved sessions. The password stays
        // in memory only — PuTTY does not persist it either.
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
                    self.connect(d.profile, pw, ctx.clone());
                }
                Some(d) if open => self.pw_dialog = Some(d),
                _ => {}
            }
        }
    }
}

impl App {
    fn draw_terminal(&mut self, ui: &mut egui::Ui) {
        let font_size = self.cfg.defaults.terminal.font_size;
        let font = egui::FontId::monospace(font_size);
        let (cw, ch) = {
            let g = ui
                .painter()
                .layout_no_wrap("M".to_owned(), font.clone(), egui::Color32::WHITE);
            (g.size().x.max(1.0), g.size().y.max(1.0))
        };

        let Some(sess) = &mut self.session else {
            return;
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
        let events = ui.input(|i| i.events.clone());
        for ev in events {
            match ev {
                egui::Event::Text(t) if focused => {
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
                            if let Some(((x0, y0), (x1, y1))) = sess.selection {
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
                        }
                        continue;
                    }
                    if let Some(bytes) = key_bytes(key, modifiers, app_cursor) {
                        let _ = sess.input.send(InputMsg::Data(bytes));
                    }
                }
                egui::Event::Paste(s) => {
                    let _ = sess.input.send(InputMsg::Data(s.into_bytes()));
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kb(k: egui::Key, ctrl: bool, shift: bool) -> Option<Vec<u8>> {
        let mods = egui::Modifiers { ctrl, shift, ..Default::default() };
        key_bytes(k, mods, false)
    }

    #[test]
    fn control_keys_map_to_c0() {
        assert_eq!(kb(egui::Key::C, true, false).unwrap(), vec![0x03]); // Ctrl-C
        assert_eq!(kb(egui::Key::D, true, false).unwrap(), vec![0x04]); // Ctrl-D
        assert_eq!(kb(egui::Key::Space, true, false).unwrap(), vec![0x00]);
    }

    #[test]
    fn navigation_sequences() {
        assert_eq!(kb(egui::Key::ArrowUp, false, false).unwrap(), b"\x1b[A".to_vec());
        assert_eq!(kb(egui::Key::Delete, false, false).unwrap(), b"\x1b[3~".to_vec());
        assert_eq!(kb(egui::Key::Enter, false, false).unwrap(), b"\r".to_vec());
        assert_eq!(kb(egui::Key::Backspace, false, false).unwrap(), vec![0x7f]);
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
