//! Cell-level terminal data model.
//!
//! PuTTY's `termchar`/`termline` in `terminal/terminal.h`. Kept deliberately
//! small and `Copy`-friendly so scrollback stays cheap.

/// A colour as understood by the emulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Color {
    #[default]
    Default,
    /// 0–255 palette index (16 ANSI + 216 cube + 24 grey).
    Indexed(u8),
    Rgb(u8, u8, u8),
}

/// SGR attributes packed into a small struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Attrs {
    pub fg: Color,
    pub bg: Color,
    pub bold: bool,
    pub dim: bool,
    pub italic: bool,
    pub underline: bool,
    pub blink: bool,
    pub reverse: bool,
    pub strike: bool,
}

impl Attrs {
    pub fn reset(&mut self) {
        *self = Attrs::default();
    }
}

/// One character cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub attrs: Attrs,
    /// 1 = normal, 2 = wide (left half), 0 = right half of a wide char.
    pub width: u8,
}

impl Default for Cell {
    fn default() -> Self {
        Cell { ch: ' ', attrs: Attrs::default(), width: 1 }
    }
}

impl Cell {
    pub fn blank(attrs: Attrs) -> Self {
        Cell { ch: ' ', attrs, width: 1 }
    }

    /// A cell is "empty" when it is a plain space with default attributes.
    pub fn is_blank(&self) -> bool {
        self.ch == ' ' && self.width == 1 && self.attrs == Attrs::default()
    }
}

/// Build a row of `cols` blanks.
pub fn blank_row(cols: usize, attrs: Attrs) -> Vec<Cell> {
    vec![Cell::blank(attrs); cols]
}
