//! Non-interactive command execution (the `plink host cmd` equivalent).
//!
//! Opens a session channel, sends `exec`, streams stdout/stderr separately and
//! returns the remote exit status. No PTY is requested, so programs behave as
//! they would under `ssh host cmd` (line buffered, no job control).

use crate::error::{PtError, Result};
use crate::session::ClientHandler;
use russh::client::Handle;
use russh::ChannelMsg;

/// A chunk of remote output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecChunk {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

/// Run `command` and feed output to `on_chunk` as it arrives.
///
/// Returns the remote exit status when the server reports one.
pub async fn exec<F>(
    handle: &Handle<ClientHandler>,
    command: &str,
    mut on_chunk: F,
) -> Result<Option<u32>>
where
    F: FnMut(ExecChunk),
{
    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| PtError::Channel(format!("open session: {e}")))?;
    channel
        .exec(true, command.as_bytes().to_vec())
        .await
        .map_err(|e| PtError::Channel(format!("exec request: {e}")))?;

    let mut status = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => on_chunk(ExecChunk::Stdout(data.to_vec())),
            ChannelMsg::ExtendedData { data, ext } => {
                if ext == 1 {
                    on_chunk(ExecChunk::Stderr(data.to_vec()));
                }
            }
            ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
            ChannelMsg::Eof => {}
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    let _ = channel.close().await;
    Ok(status)
}

/// Run `command`, buffering all output. Useful for tests and for `pt --capture`.
pub async fn exec_capture(
    handle: &Handle<ClientHandler>,
    command: &str,
) -> Result<(Vec<u8>, Vec<u8>, Option<u32>)> {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let status = exec(handle, command, |c| match c {
        ExecChunk::Stdout(d) => out.extend_from_slice(&d),
        ExecChunk::Stderr(d) => err.extend_from_slice(&d),
    })
    .await?;
    Ok((out, err, status))
}
