//! Error model for the whole `pt-*` stack.
//!
//! Library code returns [`PtError`]; the CLI turns it into a human sentence.
//! Every variant carries enough context to explain *what to do next*, mirroring
//! PuTTY's habit of printing an actionable diagnostic instead of a bare errno.

use std::fmt;

/// Everything that can go wrong while establishing or using an SSH session.
#[derive(Debug, thiserror::Error)]
pub enum PtError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("cannot resolve {0}")]
    Resolve(String),
    #[error("cannot connect to {0}")]
    Connect(String),
    #[error("proxy error: {0}")]
    Proxy(String),
    #[error("host key rejected: {0}")]
    HostKey(String),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("channel error: {0}")]
    Channel(String),
    #[error("sftp error: {0}")]
    Sftp(String),
    #[error("port forwarding error: {0}")]
    Forward(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<russh::Error> for PtError {
    fn from(e: russh::Error) -> Self {
        match &e {
            russh::Error::NoAuthMethod => PtError::Auth("server offers no usable method".into()),
            russh::Error::ConnectionTimeout => {
                PtError::Connect("handshake timed out (network or host key prompt?)".into())
            }
            _ => PtError::Protocol(e.to_string()),
        }
    }
}

impl From<russh::keys::Error> for PtError {
    fn from(e: russh::keys::Error) -> Self {
        // russh reports a *changed* key via this variant; keep it actionable.
        match &e {
            russh::keys::Error::KeyChanged { line } => PtError::HostKey(format!(
                "the server key differs from known_hosts line {line}; \
                 if the host was legitimately rekeyed, remove that line and reconnect"
            )),
            _ => PtError::Config(format!("key error: {e}")),
        }
    }
}

pub type Result<T> = std::result::Result<T, PtError>;

/// A tiny helper for mapping a foreign error into a contextual message.
pub fn ctx<E: fmt::Display>(what: &str, e: E) -> PtError {
    PtError::Protocol(format!("{what}: {e}"))
}
