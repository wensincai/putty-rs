//! `pt-core` — protocol and session core of the PuTTY→Rust rewrite.
//!
//! Layering (see `docs/PuTTY改写_架构设计.md`):
//!
//! ```text
//! pt-cli / pt-gui        front ends (keyboard, rendering, prompts)
//!        │
//!     pt-core             session orchestration + SSH via russh
//!        │
//!     pt-term             terminal model (no I/O)
//! ```
//!
//! This crate owns everything that talks to the network or the filesystem;
//! `pt-term` stays pure so it can be unit-tested deterministically.

#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod error;
pub mod exec;
pub mod forward;
pub mod known_hosts;
pub mod proxy;
pub mod session;
pub mod shell;
pub mod sftp;

pub use error::{PtError, Result};

/// Re-export the key types most callers need.
pub use config::{
    AuthConfig, AuthMethod, Config, ForwardSpec, HostKeyPolicy, ProxyConfig, SessionProfile,
};
pub use session::{connect, ConnectOptions, Connected, HostKeyInfo};
