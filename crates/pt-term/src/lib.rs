//! `pt-term` — terminal emulator model (no I/O).
//!
//! Feed remote bytes with [`Screen::feed`], read cells back for rendering, and
//! send keystrokes separately. This crate deliberately knows nothing about
//! sockets, SSH or UI toolkits so it can be tested with byte strings and reused
//! by both the CLI and the GUI.

#![forbid(unsafe_code)]

pub mod cell;
pub mod screen;

pub use cell::{blank_row, Attrs, Cell, Color};
pub use screen::{Cursor, Modes, Screen};
