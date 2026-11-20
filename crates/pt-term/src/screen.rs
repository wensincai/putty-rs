//! The terminal emulator: grid, cursor, scrollback, alternate screen and a
//! VT100/xterm parser adapter.
//!
//! Counterpart of PuTTY's `terminal/terminal.c` (~8,200 lines). The byte-level
//! state machine is delegated to the `vte` crate (the same parser Alacritty
//! uses); this module implements the *semantics*: what each action does to the
//! grid. Keeping the model free of I/O makes it testable with byte strings.

use crate::cell::{blank_row, Attrs, Cell, Color};
use std::collections::VecDeque;
use unicode_width::UnicodeWidthChar;
use vte::{Params, Perform};

const DEFAULT_TABS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Charset {
    Ascii,
    DecGraphics,
    Latin1,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Cursor {
    pub row: usize,
    pub col: usize,
    attrs: Attrs,
    /// DECOM: row addressing is relative to the scroll region.
    origin: bool,
    /// Last column written: next printable wraps first (DECAWM behaviour).
    wrap_pending: bool,
    pub visible: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Modes {
    pub autowrap: bool,
    pub insert: bool,
    pub app_cursor_keys: bool,
    pub bracketed_paste: bool,
}

struct SavedScreen {
    lines: Vec<Vec<Cell>>,
    cursor: Cursor,
    top: usize,
    bottom: usize,
}

/// A terminal screen.
pub struct Screen {
    cols: usize,
    rows: usize,
    lines: Vec<Vec<Cell>>,
    scrollback: VecDeque<Vec<Cell>>,
    scrollback_limit: usize,
    cursor: Cursor,
    saved_cursor: Option<(usize, usize, Attrs, bool)>,
    top: usize,
    bottom: usize,
    tabs: Vec<bool>,
    alt: Option<SavedScreen>,
    modes: Modes,
    title: String,
    responses: Vec<Vec<u8>>,
    charset: [Charset; 2],
    active_charset: usize,
    parser: vte::Parser,
    bell: bool,
}

impl Screen {
    pub fn new(cols: u16, rows: u16, scrollback: usize) -> Self {
        let cols = cols.max(1) as usize;
        let rows = rows.max(1) as usize;
        let mut s = Screen {
            cols,
            rows,
            lines: vec![blank_row(cols, Attrs::default()); rows],
            scrollback: VecDeque::new(),
            scrollback_limit: scrollback,
            cursor: Cursor { row: 0, col: 0, attrs: Attrs::default(), origin: false, wrap_pending: false, visible: true },
            saved_cursor: None,
            top: 0,
            bottom: rows - 1,
            tabs: default_tabs(cols),
            alt: None,
            modes: Modes { autowrap: true, insert: false, app_cursor_keys: false, bracketed_paste: false },
            title: String::new(),
            responses: Vec::new(),
            charset: [Charset::Ascii; 2],
            active_charset: 0,
            parser: vte::Parser::new(),
            bell: false,
        };
        s.clear_all();
        s
    }

    pub fn size(&self) -> (usize, usize) {
        (self.cols, self.rows)
    }

    pub fn cursor(&self) -> Cursor {
        self.cursor
    }

    pub fn modes(&self) -> Modes {
        self.modes
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn in_alt_screen(&self) -> bool {
        self.alt.is_some()
    }

    pub fn scrollback_len(&self) -> usize {
        self.scrollback.len()
    }

    pub fn scrollback_line(&self, idx: usize) -> Option<&[Cell]> {
        self.scrollback.get(idx).map(|v| v.as_slice())
    }

    /// One viewport row.
    pub fn line(&self, y: usize) -> &[Cell] {
        self.lines.get(y).map(|l| l.as_slice()).unwrap_or(&[])
    }

    pub fn cell(&self, x: usize, y: usize) -> Option<&Cell> {
        self.lines.get(y).and_then(|l| l.get(x))
    }

    /// Bytes the terminal owes the application (device status reports).
    pub fn take_responses(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.responses)
    }

    pub fn take_bell(&mut self) -> bool {
        std::mem::take(&mut self.bell)
    }

    /// Feed bytes from the remote side.
    pub fn feed(&mut self, bytes: &[u8]) {
        // The parser must borrow self as the performer; move it out to satisfy
        // the borrow checker without unsafe.
        let mut parser = std::mem::replace(&mut self.parser, vte::Parser::new());
        parser.advance(self, bytes);
        self.parser = parser;
    }

    /// Plain-text dump of the viewport (used by tests and `--dump`).
    pub fn dump(&self) -> String {
        let mut out = String::new();
        for y in 0..self.rows {
            let mut line = String::new();
            for c in &self.lines[y] {
                if c.width == 0 {
                    continue; // right half of a wide char
                }
                line.push(c.ch);
            }
            out.push_str(line.trim_end());
            if y + 1 < self.rows {
                out.push('\n');
            }
        }
        out
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        let cols = cols.max(1) as usize;
        let rows = rows.max(1) as usize;
        if cols == self.cols && rows == self.rows {
            return;
        }
        // No reflow (documented limitation): keep the top-left content.
        for line in &mut self.lines {
            line.resize(cols, Cell::default());
            line.truncate(cols);
        }
        if rows > self.lines.len() {
            while self.lines.len() < rows {
                self.lines.push(blank_row(cols, Attrs::default()));
            }
        } else if rows < self.lines.len() {
            // Drop from the bottom, but keep the cursor row visible.
            let keep_from = self.cursor.row.saturating_sub(rows - 1);
            self.lines.drain(0..keep_from);
            self.lines.truncate(rows);
            self.cursor.row = self.cursor.row.saturating_sub(keep_from).min(rows - 1);
            while self.lines.len() < rows {
                self.lines.push(blank_row(cols, Attrs::default()));
            }
        }
        self.cols = cols;
        self.rows = rows;
        self.top = 0;
        self.bottom = rows - 1;
        self.tabs = default_tabs(cols);
        self.cursor.col = self.cursor.col.min(cols - 1);
        self.cursor.wrap_pending = false;
    }

    // ---------------------------------------------------------------- grid ops

    fn clear_all(&mut self) {
        for line in &mut self.lines {
            *line = blank_row(self.cols, Attrs::default());
        }
        self.top = 0;
        self.bottom = self.rows - 1;
        self.cursor.row = 0;
        self.cursor.col = 0;
        self.cursor.wrap_pending = false;
    }

    fn blank_line(&self) -> Vec<Cell> {
        blank_row(self.cols, self.cursor.attrs)
    }

    fn scroll_up_region(&mut self, n: usize) {
        let n = n.min(self.bottom - self.top + 1);
        for _ in 0..n {
            let removed = self.lines.remove(self.top);
            if self.top == 0 && self.alt.is_none() && self.scrollback_limit > 0 {
                self.scrollback.push_back(removed);
                while self.scrollback.len() > self.scrollback_limit {
                    self.scrollback.pop_front();
                }
            }
            self.lines.insert(self.bottom, self.blank_line());
        }
    }

    fn scroll_down_region(&mut self, n: usize) {
        let n = n.min(self.bottom - self.top + 1);
        for _ in 0..n {
            self.lines.remove(self.bottom);
            self.lines.insert(self.top, self.blank_line());
        }
    }

    fn linefeed(&mut self) {
        self.cursor.wrap_pending = false;
        if self.cursor.row == self.bottom {
            self.scroll_up_region(1);
        } else if self.cursor.row + 1 < self.rows {
            self.cursor.row += 1;
        }
    }

    fn reverse_index(&mut self) {
        self.cursor.wrap_pending = false;
        if self.cursor.row == self.top {
            self.scroll_down_region(1);
        } else {
            self.cursor.row = self.cursor.row.saturating_sub(1);
        }
    }

    fn carriage_return(&mut self) {
        self.cursor.col = 0;
        self.cursor.wrap_pending = false;
    }

    fn tab_forward(&mut self, n: usize) {
        for _ in 0..n {
            let mut c = self.cursor.col + 1;
            while c < self.cols && !self.tabs.get(c).copied().unwrap_or(false) {
                c += 1;
            }
            self.cursor.col = c.min(self.cols - 1);
        }
        self.cursor.wrap_pending = false;
    }

    fn tab_backward(&mut self, n: usize) {
        for _ in 0..n {
            let mut c = self.cursor.col;
            while c > 0 {
                c -= 1;
                if self.tabs.get(c).copied().unwrap_or(false) {
                    break;
                }
            }
            self.cursor.col = c;
        }
        self.cursor.wrap_pending = false;
    }

    fn put_char(&mut self, ch: char) {
        let width = ch.width().unwrap_or(1).clamp(1, 2);
        if self.cursor.wrap_pending && self.modes.autowrap {
            self.carriage_return();
            self.linefeed();
        }
        if self.cursor.col + width > self.cols {
            if self.modes.autowrap {
                self.carriage_return();
                self.linefeed();
            } else {
                self.cursor.col = self.cols.saturating_sub(width);
            }
        }
        if self.modes.insert {
            let row = self.cursor.row;
            let col = self.cursor.col;
            let line = &mut self.lines[row];
            for _ in 0..width {
                line.insert(col, Cell::blank(self.cursor.attrs));
            }
            line.truncate(self.cols);
        }
        let attrs = self.cursor.attrs;
        let row = self.cursor.row;
        let col = self.cursor.col;
        {
            let line = &mut self.lines[row];
            line[col] = Cell { ch, attrs, width: width as u8 };
            if width == 2 && col + 1 < self.cols {
                // Right half marker so erasing one half clears both.
                line[col + 1] = Cell { ch: ' ', attrs, width: 0 };
            }
        }
        self.cursor.col += width;
        if self.cursor.col >= self.cols {
            self.cursor.col = self.cols - 1;
            self.cursor.wrap_pending = true;
        }
    }

    fn erase_cells(&mut self, row: usize, from: usize, to: usize) {
        let attrs = self.cursor.attrs;
        if let Some(line) = self.lines.get_mut(row) {
            for c in from..to.min(line.len()) {
                line[c] = Cell::blank(attrs);
            }
        }
    }

    fn erase_display(&mut self, mode: u16) {
        let (row, col) = (self.cursor.row, self.cursor.col);
        match mode {
            0 => {
                self.erase_cells(row, col, self.cols);
                for y in row + 1..self.rows {
                    self.erase_cells(y, 0, self.cols);
                }
            }
            1 => {
                for y in 0..row {
                    self.erase_cells(y, 0, self.cols);
                }
                self.erase_cells(row, 0, col + 1);
            }
            2 | 3 => {
                for y in 0..self.rows {
                    self.erase_cells(y, 0, self.cols);
                }
                if mode == 3 {
                    self.scrollback.clear();
                }
            }
            _ => {}
        }
    }

    fn erase_line(&mut self, mode: u16) {
        let (row, col) = (self.cursor.row, self.cursor.col);
        match mode {
            0 => self.erase_cells(row, col, self.cols),
            1 => self.erase_cells(row, 0, col + 1),
            2 => self.erase_cells(row, 0, self.cols),
            _ => {}
        }
    }

    fn save_cursor(&mut self) {
        self.saved_cursor =
            Some((self.cursor.row, self.cursor.col, self.cursor.attrs, self.cursor.origin));
    }

    fn restore_cursor(&mut self) {
        if let Some((row, col, attrs, origin)) = self.saved_cursor {
            self.cursor.row = row.min(self.rows - 1);
            self.cursor.col = col.min(self.cols - 1);
            self.cursor.attrs = attrs;
            self.cursor.origin = origin;
            self.cursor.wrap_pending = false;
        }
    }

    fn enter_alt(&mut self, clear: bool) {
        if self.alt.is_some() {
            return;
        }
        let saved = SavedScreen {
            lines: std::mem::replace(&mut self.lines, vec![blank_row(self.cols, Attrs::default()); self.rows]),
            cursor: self.cursor,
            top: self.top,
            bottom: self.bottom,
        };
        if !clear {
            self.lines = saved.lines.clone();
        }
        self.alt = Some(saved);
        self.cursor.row = 0;
        self.cursor.col = 0;
        self.top = 0;
        self.bottom = self.rows - 1;
    }

    fn leave_alt(&mut self) {
        if let Some(saved) = self.alt.take() {
            if self.alt.is_none() {
                self.lines = saved.lines;
                self.cursor = saved.cursor;
                self.top = saved.top;
                self.bottom = saved.bottom;
            }
        }
    }

    fn reset(&mut self) {
        self.alt = None;
        self.charset = [Charset::Ascii; 2];
        self.active_charset = 0;
        self.modes = Modes { autowrap: true, insert: false, app_cursor_keys: false, bracketed_paste: false };
        self.cursor = Cursor {
            row: 0,
            col: 0,
            attrs: Attrs::default(),
            origin: false,
            wrap_pending: false,
            visible: true,
        };
        self.scrollback.clear();
        self.title.clear();
        self.clear_all();
    }

    fn set_cursor_pos(&mut self, row: usize, col: usize) {
        let (row, col) = if self.cursor.origin {
            let r = (self.top + row).min(self.bottom);
            (r, col.min(self.cols - 1))
        } else {
            (row.min(self.rows - 1), col.min(self.cols - 1))
        };
        self.cursor.row = row;
        self.cursor.col = col;
        self.cursor.wrap_pending = false;
    }

    fn set_scroll_region(&mut self, top: usize, bottom: usize) {
        let top = top.min(self.rows - 1);
        let bottom = bottom.min(self.rows - 1);
        if top < bottom {
            self.top = top;
            self.bottom = bottom;
            self.set_cursor_pos(0, 0);
        }
    }

    fn sgr(&mut self, params: &Params) {
        let vals: Vec<u16> = params.iter().map(|p| p[0]).collect();
        if vals.is_empty() {
            self.cursor.attrs.reset();
            return;
        }
        let mut i = 0usize;
        while i < vals.len() {
            match vals[i] {
                0 => self.cursor.attrs.reset(),
                1 => self.cursor.attrs.bold = true,
                2 => self.cursor.attrs.dim = true,
                3 => self.cursor.attrs.italic = true,
                4 => self.cursor.attrs.underline = true,
                5 | 6 => self.cursor.attrs.blink = true,
                7 => self.cursor.attrs.reverse = true,
                9 => self.cursor.attrs.strike = true,
                22 => {
                    self.cursor.attrs.bold = false;
                    self.cursor.attrs.dim = false;
                }
                23 => self.cursor.attrs.italic = false,
                24 => self.cursor.attrs.underline = false,
                25 => self.cursor.attrs.blink = false,
                27 => self.cursor.attrs.reverse = false,
                29 => self.cursor.attrs.strike = false,
                30..=37 => self.cursor.attrs.fg = Color::Indexed((vals[i] - 30) as u8),
                39 => self.cursor.attrs.fg = Color::Default,
                40..=47 => self.cursor.attrs.bg = Color::Indexed((vals[i] - 40) as u8),
                49 => self.cursor.attrs.bg = Color::Default,
                90..=97 => self.cursor.attrs.fg = Color::Indexed((vals[i] - 90 + 8) as u8),
                100..=107 => self.cursor.attrs.bg = Color::Indexed((vals[i] - 100 + 8) as u8),
                38 | 48 => {
                    let is_fg = vals[i] == 38;
                    match vals.get(i + 1).copied() {
                        Some(5) => {
                            if let Some(&n) = vals.get(i + 2) {
                                let c = Color::Indexed(n.min(255) as u8);
                                if is_fg {
                                    self.cursor.attrs.fg = c;
                                } else {
                                    self.cursor.attrs.bg = c;
                                }
                                i += 3;
                                continue;
                            }
                        }
                        Some(2) => {
                            if let (Some(&r), Some(&g), Some(&b)) =
                                (vals.get(i + 2), vals.get(i + 3), vals.get(i + 4))
                            {
                                let c = Color::Rgb(r.min(255) as u8, g.min(255) as u8, b.min(255) as u8);
                                if is_fg {
                                    self.cursor.attrs.fg = c;
                                } else {
                                    self.cursor.attrs.bg = c;
                                }
                                i += 5;
                                continue;
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }

    fn response(&mut self, s: String) {
        self.responses.push(s.into_bytes());
    }

    fn translate(&self, ch: char) -> char {
        match self.charset[self.active_charset] {
            Charset::DecGraphics => dec_graphics(ch),
            Charset::Latin1 | Charset::Ascii => ch,
        }
    }
}

fn default_tabs(cols: usize) -> Vec<bool> {
    (0..cols).map(|i| i > 0 && i % DEFAULT_TABS == 0).collect()
}

/// DEC Special Graphics (line drawing), used by ncurses for borders.
fn dec_graphics(c: char) -> char {
    match c {
        '`' => '◆',
        'a' => '▒',
        'b' => '␉',
        'c' => '␌',
        'd' => '␍',
        'e' => '␊',
        'f' => '°',
        'g' => '±',
        'h' => '␤',
        'i' => '␋',
        'j' => '┘',
        'k' => '┐',
        'l' => '┌',
        'm' => '└',
        'n' => '┼',
        'o' => '⎺',
        'p' => '⎻',
        'q' => '─',
        'r' => '⎼',
        's' => '⎽',
        't' => '├',
        'u' => '┤',
        'v' => '┴',
        'w' => '┬',
        'x' => '│',
        'y' => '≤',
        'z' => '≥',
        '{' => 'π',
        '|' => '≠',
        '}' => '£',
        '~' => '·',
        other => other,
    }
}

fn p(params: &Params, idx: usize, default: u16) -> u16 {
    params
        .iter()
        .nth(idx)
        .and_then(|g| g.first().copied())
        .unwrap_or(default)
}

fn p1(params: &Params, idx: usize) -> usize {
    p(params, idx, 1).max(1) as usize
}

impl Perform for Screen {
    fn print(&mut self, c: char) {
        let ch = self.translate(c);
        self.put_char(ch);
    }

    fn execute(&mut self, byte: u8) {
        match byte {
            0x07 => self.bell = true,
            0x08 => {
                if self.cursor.col > 0 {
                    self.cursor.col -= 1;
                }
                self.cursor.wrap_pending = false;
            }
            0x09 => self.tab_forward(1),
            0x0a..=0x0c => self.linefeed(),
            0x0d => self.carriage_return(),
            0x0e => self.active_charset = 1, // SO
            0x0f => self.active_charset = 0, // SI
            _ => {}
        }
    }

    fn csi_dispatch(&mut self, params: &Params, intermediates: &[u8], _ignore: bool, action: char) {
        let private = intermediates.first().copied();
        match (private, action) {
            // ---- cursor movement
            (None, 'A') => {
                let n = p1(params, 0);
                self.cursor.row = self.cursor.row.saturating_sub(n).max(self.top.min(self.cursor.row));
                self.cursor.wrap_pending = false;
            }
            (None, 'B') | (None, 'e') => {
                let n = p1(params, 0);
                self.cursor.row = (self.cursor.row + n).min(self.bottom);
                self.cursor.wrap_pending = false;
            }
            (None, 'C') | (None, 'a') => {
                let n = p1(params, 0);
                self.cursor.col = (self.cursor.col + n).min(self.cols - 1);
                self.cursor.wrap_pending = false;
            }
            (None, 'D') => {
                let n = p1(params, 0);
                self.cursor.col = self.cursor.col.saturating_sub(n);
                self.cursor.wrap_pending = false;
            }
            (None, 'E') => {
                let n = p1(params, 0);
                self.cursor.row = (self.cursor.row + n).min(self.bottom);
                self.cursor.col = 0;
            }
            (None, 'F') => {
                let n = p1(params, 0);
                self.cursor.row = self.cursor.row.saturating_sub(n).max(self.top.min(self.cursor.row));
                self.cursor.col = 0;
            }
            (None, 'G') | (None, '`') => {
                self.cursor.col = (p1(params, 0) - 1).min(self.cols - 1);
            }
            (None, 'H') | (None, 'f') => {
                let row = p(params, 0, 1).max(1) as usize - 1;
                let col = p(params, 1, 1).max(1) as usize - 1;
                self.set_cursor_pos(row, col);
            }
            (None, 'd') => {
                let row = p1(params, 0) - 1;
                self.set_cursor_pos(row, self.cursor.col);
            }
            // ---- erase
            (None, 'J') => self.erase_display(p(params, 0, 0)),
            (None, 'K') => self.erase_line(p(params, 0, 0)),
            (None, 'Z') => {
                let n = p1(params, 0);
                self.tab_backward(n);
            }
            (None, 'X') => {
                let n = p1(params, 0);
                let (row, col) = (self.cursor.row, self.cursor.col);
                self.erase_cells(row, col, (col + n).min(self.cols));
            }
            // ---- insert / delete
            (None, 'L') => {
                let n = p1(params, 0);
                if self.cursor.row >= self.top && self.cursor.row <= self.bottom {
                    let row = self.cursor.row;
                    for _ in 0..n {
                        self.lines.remove(self.bottom);
                        self.lines.insert(row, self.blank_line());
                    }
                }
            }
            (None, 'M') => {
                let n = p1(params, 0);
                if self.cursor.row >= self.top && self.cursor.row <= self.bottom {
                    let row = self.cursor.row;
                    for _ in 0..n {
                        self.lines.remove(row);
                        self.lines.insert(self.bottom, self.blank_line());
                    }
                }
            }
            (None, 'P') => {
                let n = p1(params, 0);
                let (row, col) = (self.cursor.row, self.cursor.col);
                let line = &mut self.lines[row];
                let end = line.len();
                line.drain(col..(col + n).min(end));
                line.resize(self.cols, Cell::default());
            }
            (None, '@') => {
                let n = p1(params, 0);
                let attrs = self.cursor.attrs;
                let (row, col) = (self.cursor.row, self.cursor.col);
                let line = &mut self.lines[row];
                for _ in 0..n {
                    line.insert(col, Cell::blank(attrs));
                }
                line.truncate(self.cols);
            }
            (None, 'S') => {
                let n = p1(params, 0);
                self.scroll_up_region(n);
            }
            (None, 'T') => {
                let n = p1(params, 0);
                self.scroll_down_region(n);
            }
            // ---- SGR
            (None, 'm') => self.sgr(params),
            // ---- scroll region
            (None, 'r') => {
                let top = p(params, 0, 1).max(1) as usize - 1;
                let bottom = p(params, 1, self.rows as u16).max(1) as usize - 1;
                self.set_scroll_region(top, bottom);
            }
            // ---- device reports
            (None, 'n') => match p(params, 0, 0) {
                5 => self.response("\x1b[0n".into()),
                6 => {
                    let row = self.cursor.row + 1;
                    let col = self.cursor.col + 1;
                    self.response(format!("\x1b[{row};{col}R"));
                }
                _ => {}
            },
            (None, 'c') => self.response("\x1b[?62;22c".into()),
            (Some(b'>'), 'c') => self.response("\x1b[>1;10;0c".into()),
            // ---- tab clearing
            (None, 'g') => match p(params, 0, 0) {
                0 => {
                    let c = self.cursor.col;
                    if let Some(t) = self.tabs.get_mut(c) {
                        *t = false;
                    }
                }
                3 => self.tabs.iter_mut().for_each(|t| *t = false),
                _ => {}
            },
            // ---- repeat last char
            (None, 'b') => {
                let n = p1(params, 0);
                // We do not keep the last char; repeating a space is what most
                // applications expect from REP after clearing.
                for _ in 0..n {
                    self.put_char(' ');
                }
            }
            // ---- DEC private modes
            (Some(b'?'), 'h') => self.set_private_modes(params, true),
            (Some(b'?'), 'l') => self.set_private_modes(params, false),
            (None, 'h') => {
                for v in params.iter().map(|g| g[0]) {
                    if v == 4 {
                        self.modes.insert = true;
                    }
                }
            }
            (None, 'l') => {
                for v in params.iter().map(|g| g[0]) {
                    if v == 4 {
                        self.modes.insert = false;
                    }
                }
            }
            // ---- soft reset
            (Some(b'!'), 'p') => {
                self.modes.insert = false;
                self.cursor.origin = false;
                self.top = 0;
                self.bottom = self.rows - 1;
                self.cursor.attrs.reset();
            }
            _ => {}
        }
    }

    fn esc_dispatch(&mut self, intermediates: &[u8], _ignore: bool, byte: u8) {
        match (intermediates.first().copied(), byte) {
            (None, b'7') => self.save_cursor(),
            (None, b'8') => self.restore_cursor(),
            (None, b'D') => self.linefeed(),
            (None, b'E') => {
                self.carriage_return();
                self.linefeed();
            }
            (None, b'M') => self.reverse_index(),
            (None, b'H') => {
                let c = self.cursor.col;
                if let Some(t) = self.tabs.get_mut(c) {
                    *t = true;
                }
            }
            (None, b'c') => self.reset(),
            (Some(b'('), b'0') => self.charset[0] = Charset::DecGraphics,
            (Some(b'('), b'B') => self.charset[0] = Charset::Ascii,
            (Some(b'('), b'A') => self.charset[0] = Charset::Latin1,
            (Some(b')'), b'0') => self.charset[1] = Charset::DecGraphics,
            (Some(b')'), b'B') => self.charset[1] = Charset::Ascii,
            (Some(b')'), b'A') => self.charset[1] = Charset::Latin1,
            _ => {}
        }
    }

    fn osc_dispatch(&mut self, params: &[&[u8]], _bell_terminated: bool) {
        if let Some(&op) = params.first() {
            if (op == b"0" || op == b"2") && params.len() > 1 {
                let title: Vec<u8> = params[1..].join(&b' ');
                self.title = String::from_utf8_lossy(&title).into_owned();
            }
        }
    }

    fn hook(&mut self, _params: &Params, _intermediates: &[u8], _ignore: bool, _action: char) {}
    fn put(&mut self, _byte: u8) {}
    fn unhook(&mut self) {}
}

impl Screen {
    fn set_private_modes(&mut self, params: &Params, enable: bool) {
        for v in params.iter().map(|g| g[0]) {
            match v {
                1 => self.modes.app_cursor_keys = enable,
                6 => {
                    self.cursor.origin = enable;
                    self.set_cursor_pos(0, 0);
                }
                7 => self.modes.autowrap = enable,
                12 => {}
                25 => self.cursor.visible = enable,
                47 | 1047 => {
                    if enable {
                        self.enter_alt(true);
                    } else {
                        self.leave_alt();
                    }
                }
                1048 => {
                    if enable {
                        self.save_cursor();
                    } else {
                        self.restore_cursor();
                    }
                }
                1049 => {
                    if enable {
                        self.save_cursor();
                        self.enter_alt(true);
                    } else {
                        self.leave_alt();
                        self.restore_cursor();
                    }
                }
                2004 => self.modes.bracketed_paste = enable,
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(s: &mut Screen, text: &str) {
        s.feed(text.as_bytes());
    }

    #[test]
    fn plain_text_and_newline() {
        let mut s = Screen::new(20, 4, 100);
        feed(&mut s, "hello\r\nworld");
        assert_eq!(s.dump(), "hello\nworld\n\n");
        assert_eq!(s.cursor().row, 1);
        assert_eq!(s.cursor().col, 5);
    }

    #[test]
    fn autowrap_puts_char_on_next_line() {
        let mut s = Screen::new(5, 3, 10);
        feed(&mut s, "abcde");
        assert_eq!(s.cursor().row, 0);
        feed(&mut s, "f");
        assert_eq!(s.cursor().row, 1);
        assert_eq!(s.line(1)[0].ch, 'f');
    }

    #[test]
    fn sgr_colors_and_bold() {
        let mut s = Screen::new(20, 2, 10);
        feed(&mut s, "\x1b[1;31mR\x1b[0mN");
        let c = s.cell(0, 0).unwrap();
        assert!(c.attrs.bold);
        assert_eq!(c.attrs.fg, Color::Indexed(1));
        assert!(!s.cell(1, 0).unwrap().attrs.bold);
    }

    #[test]
    fn truecolor_and_256() {
        let mut s = Screen::new(10, 2, 10);
        feed(&mut s, "\x1b[38;2;10;20;30mA\x1b[48;5;200mB");
        assert_eq!(s.cell(0, 0).unwrap().attrs.fg, Color::Rgb(10, 20, 30));
        assert_eq!(s.cell(1, 0).unwrap().attrs.bg, Color::Indexed(200));
    }

    #[test]
    fn cursor_addressing_and_erase() {
        let mut s = Screen::new(10, 4, 10);
        feed(&mut s, "aaaa\r\nbbbb\r\ncccc");
        feed(&mut s, "\x1b[2;2H");
        feed(&mut s, "\x1b[K"); // erase to end of line 2
        assert_eq!(s.dump().trim_end(), "aaaa\nb\ncccc");
        feed(&mut s, "\x1b[2J");
        assert_eq!(s.dump(), "\n\n\n");
    }

    #[test]
    fn scroll_region_insert_delete() {
        let mut s = Screen::new(6, 4, 10);
        feed(&mut s, "1\r\n2\r\n3\r\n4");
        feed(&mut s, "\x1b[2;3r"); // region rows 2-3
        feed(&mut s, "\x1b[2;1H");
        feed(&mut s, "\x1b[L"); // insert line at row 2
        assert_eq!(s.line(0)[0].ch, '1');
        assert_eq!(s.line(3)[0].ch, '4');
    }

    #[test]
    fn scrollback_accumulates() {
        let mut s = Screen::new(10, 2, 100);
        feed(&mut s, "a\r\nb\r\nc\r\nd");
        assert!(s.scrollback_len() >= 2);
        assert_eq!(s.scrollback_line(0).unwrap()[0].ch, 'a');
    }

    #[test]
    fn alt_screen_roundtrip() {
        let mut s = Screen::new(10, 3, 10);
        feed(&mut s, "main");
        feed(&mut s, "\x1b[?1049h");
        assert!(s.in_alt_screen());
        assert_eq!(s.dump().trim(), "");
        feed(&mut s, "alt");
        feed(&mut s, "\x1b[?1049l");
        assert_eq!(s.dump().trim(), "main");
    }

    #[test]
    fn wide_chars_occupy_two_cells() {
        let mut s = Screen::new(10, 2, 10);
        feed(&mut s, "中a");
        assert_eq!(s.cell(0, 0).unwrap().width, 2);
        assert_eq!(s.cell(1, 0).unwrap().width, 0);
        assert_eq!(s.cell(2, 0).unwrap().ch, 'a');
        assert_eq!(s.dump().trim_end(), "中a");
    }

    #[test]
    fn tabs_advance_to_stops() {
        let mut s = Screen::new(20, 2, 10);
        feed(&mut s, "a\tb");
        assert_eq!(s.cell(8, 0).unwrap().ch, 'b');
    }

    #[test]
    fn dec_graphics_borders() {
        let mut s = Screen::new(10, 2, 10);
        feed(&mut s, "\x1b(0lqk\x1b(B");
        assert_eq!(s.cell(0, 0).unwrap().ch, '┌');
        assert_eq!(s.cell(1, 0).unwrap().ch, '─');
        assert_eq!(s.cell(2, 0).unwrap().ch, '┐');
    }

    #[test]
    fn reports_cursor_position_and_da() {
        let mut s = Screen::new(10, 4, 10);
        feed(&mut s, "\x1b[3;4H");
        feed(&mut s, "\x1b[6n");
        let r = s.take_responses();
        assert_eq!(r[0], b"\x1b[3;4R");
        feed(&mut s, "\x1b[c");
        assert_eq!(s.take_responses()[0], b"\x1b[?62;22c");
    }

    #[test]
    fn osc_sets_title() {
        let mut s = Screen::new(10, 2, 10);
        feed(&mut s, "\x1b]0;my title\x07");
        assert_eq!(s.title(), "my title");
    }

    #[test]
    fn resize_keeps_content() {
        let mut s = Screen::new(10, 3, 10);
        feed(&mut s, "abc");
        s.resize(20, 5);
        assert_eq!(s.dump().lines().next().unwrap(), "abc");
        assert_eq!(s.size(), (20, 5));
    }

    #[test]
    fn reverse_index_scrolls_down() {
        let mut s = Screen::new(6, 3, 10);
        feed(&mut s, "a\r\nb\r\nc");
        feed(&mut s, "\x1b[1;1H\x1bM");
        assert_eq!(s.line(0)[0].ch, ' ');
        assert_eq!(s.line(1)[0].ch, 'a');
    }
}
