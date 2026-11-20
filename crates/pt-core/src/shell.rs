//! Interactive shell sessions: PTY negotiation, input pump, resize events.
//!
//! PuTTY splits this between `ssh/sesschan.c` (channel + pty-req) and
//! `terminal/terminal.c` (rendering). Here the channel side lives in this
//! module and rendering is the front end's job; the front end feeds bytes to
//! `pt-term` and sends keystrokes back through an [`InputMsg`] channel.

use crate::error::{PtError, Result};
use crate::session::ClientHandler;
use russh::client::Handle;
use russh::ChannelMsg;
use tokio::sync::mpsc;

/// What the front end can send to the remote shell.
#[derive(Debug, Clone)]
pub enum InputMsg {
    Data(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    /// Ctrl-D / half close.
    Eof,
}

/// What comes back.
#[derive(Debug, Clone)]
pub enum ShellChunk {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct ShellOptions {
    pub term: String,
    pub cols: u16,
    pub rows: u16,
    /// `false` gives `ssh host` semantics with redirected stdio (no PTY).
    pub want_pty: bool,
}

impl Default for ShellOptions {
    fn default() -> Self {
        ShellOptions { term: "xterm-256color".into(), cols: 80, rows: 24, want_pty: true }
    }
}

/// Open a shell and pump until the channel closes.
///
/// `on_output` is called from the async task that owns the channel, so it must
/// not block for long; the CLI/GUI push into their own queues.
pub async fn run_shell<F>(
    handle: &Handle<ClientHandler>,
    opts: &ShellOptions,
    mut input: mpsc::UnboundedReceiver<InputMsg>,
    mut on_output: F,
) -> Result<Option<u32>>
where
    F: FnMut(ShellChunk),
{
    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| PtError::Channel(format!("open session: {e}")))?;

    if opts.want_pty {
        channel
            .request_pty(true, &opts.term, opts.cols as u32, opts.rows as u32, 0, 0, &[])
            .await
            .map_err(|e| PtError::Channel(format!("pty request: {e}")))?;
    }
    channel
        .request_shell(true)
        .await
        .map_err(|e| PtError::Channel(format!("shell request: {e}")))?;

    let mut status = None;
    let mut input_open = true;
    loop {
        tokio::select! {
            biased;
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => on_output(ShellChunk::Stdout(data.to_vec())),
                    Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                        on_output(ShellChunk::Stderr(data.to_vec()))
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => status = Some(exit_status),
                    Some(ChannelMsg::Eof) => {}
                    Some(ChannelMsg::Close) | None => break,
                    _ => {}
                }
            }
            msg = input.recv(), if input_open => {
                match msg {
                    Some(InputMsg::Data(d)) => {
                        if let Err(e) = channel.data_bytes(d).await {
                            // A closed channel is a normal end-of-session.
                            tracing::debug!(error = %e, "write to channel failed");
                            break;
                        }
                    }
                    Some(InputMsg::Resize { cols, rows }) => {
                        let _ = channel.window_change(cols as u32, rows as u32, 0, 0).await;
                    }
                    Some(InputMsg::Eof) | None => {
                        input_open = false;
                        let _ = channel.eof().await;
                    }
                }
            }
        }
    }
    let _ = channel.close().await;
    Ok(status)
}
