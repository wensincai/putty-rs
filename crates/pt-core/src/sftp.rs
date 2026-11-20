//! SFTP client semantics on top of `russh-sftp`.
//!
//! PuTTY ships its own client (`ssh/sftp.c`, ~1,200 lines) and server
//! (`ssh/sftpserver.c`). We only need the client side; the wire protocol is
//! handled by `russh-sftp`, and this module adds the behaviours users care
//! about: recursion, resumable transfers, progress reporting and `mkdir -p`.

use crate::error::{PtError, Result};
use crate::session::ClientHandler;
use russh::client::Handle;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use std::io::SeekFrom;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

const CHUNK: usize = 256 * 1024;

/// One directory entry, normalised for display.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub mode: Option<u32>,
    pub mtime: Option<u32>,
}

impl Entry {
    /// `drwxr-xr-x` style mode string for `ls -l`.
    pub fn mode_string(&self) -> String {
        let m = self.mode.unwrap_or(0o644);
        let kind = if self.is_dir {
            'd'
        } else if self.is_symlink {
            'l'
        } else {
            '-'
        };
        let bit = |shift: u32, ch: char| if (m >> shift) & 1 == 1 { ch } else { '-' };
        format!(
            "{kind}{}{}{}{}{}{}{}{}{}",
            bit(8, 'r'),
            bit(7, 'w'),
            bit(6, 'x'),
            bit(5, 'r'),
            bit(4, 'w'),
            bit(3, 'x'),
            bit(2, 'r'),
            bit(1, 'w'),
            bit(0, 'x')
        )
    }
}

pub struct SftpClient {
    s: SftpSession,
}

impl SftpClient {
    /// Open the SFTP subsystem on a fresh session channel.
    pub async fn open(handle: &mut Handle<ClientHandler>) -> Result<Self> {
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| PtError::Sftp(format!("open session: {e}")))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| PtError::Sftp(format!("subsystem request: {e}")))?;
        let s = SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| PtError::Sftp(format!("sftp handshake: {e}")))?;
        Ok(SftpClient { s })
    }

    /// Absolute path of the login directory.
    pub async fn home(&self) -> Result<String> {
        self.s
            .canonicalize(".")
            .await
            .map_err(|e| PtError::Sftp(format!("canonicalize '.': {e}")))
    }

    pub async fn list(&self, path: &str) -> Result<Vec<Entry>> {
        let dir = self
            .s
            .read_dir(path)
            .await
            .map_err(|e| PtError::Sftp(format!("list {path}: {e}")))?;
        let mut out = Vec::new();
        for e in dir {
            let m = e.metadata();
            out.push(Entry {
                name: e.file_name(),
                is_dir: m.is_dir(),
                is_symlink: m.is_symlink(),
                size: m.size.unwrap_or(0),
                mode: m.permissions,
                mtime: m.mtime,
            });
        }
        out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.cmp(&b.name)));
        Ok(out)
    }

    pub async fn is_dir(&self, path: &str) -> bool {
        self.s
            .metadata(path)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false)
    }

    pub async fn size(&self, path: &str) -> Result<u64> {
        let m = self
            .s
            .metadata(path)
            .await
            .map_err(|e| PtError::Sftp(format!("stat {path}: {e}")))?;
        Ok(m.size.unwrap_or(0))
    }

    /// Download `remote` to `local`, optionally resuming at the local length.
    ///
    /// Returns the final byte count. `progress(done, total)` is called per chunk.
    pub async fn get<F>(
        &self,
        remote: &str,
        local: &Path,
        resume: bool,
        mut progress: F,
    ) -> Result<u64>
    where
        F: FnMut(u64, u64),
    {
        let total = self.size(remote).await?;
        let offset = if resume && local.exists() {
            std::fs::metadata(local).map(|m| m.len()).unwrap_or(0).min(total)
        } else {
            0
        };
        if let Some(parent) = local.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        let mut rf = self
            .s
            .open(remote)
            .await
            .map_err(|e| PtError::Sftp(format!("open remote {remote}: {e}")))?;
        if offset > 0 {
            rf.seek(SeekFrom::Start(offset))
                .await
                .map_err(|e| PtError::Sftp(format!("seek remote: {e}")))?;
        }
        let mut lf = if offset > 0 {
            tokio::fs::OpenOptions::new().append(true).open(local).await?
        } else {
            tokio::fs::File::create(local).await?
        };

        let mut buf = vec![0u8; CHUNK];
        let mut done = offset;
        progress(done, total);
        loop {
            let n = rf
                .read(&mut buf)
                .await
                .map_err(|e| PtError::Sftp(format!("read remote: {e}")))?;
            if n == 0 {
                break;
            }
            lf.write_all(&buf[..n]).await?;
            done += n as u64;
            progress(done, total);
        }
        lf.flush().await?;
        Ok(done)
    }

    /// Upload `local` to `remote`, optionally appending (resume).
    pub async fn put<F>(
        &self,
        local: &Path,
        remote: &str,
        resume: bool,
        mut progress: F,
    ) -> Result<u64>
    where
        F: FnMut(u64, u64),
    {
        let total = std::fs::metadata(local)?.len();
        let existing = if resume { self.size(remote).await.unwrap_or(0).min(total) } else { 0 };

        let mut lf = tokio::fs::File::open(local).await?;
        if existing > 0 {
            lf.seek(SeekFrom::Start(existing)).await?;
        }
        let flags = if existing > 0 {
            OpenFlags::WRITE | OpenFlags::CREATE
        } else {
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE
        };
        let mut rf = self
            .s
            .open_with_flags(remote, flags)
            .await
            .map_err(|e| PtError::Sftp(format!("open remote {remote}: {e}")))?;
        if existing > 0 {
            rf.seek(SeekFrom::Start(existing))
                .await
                .map_err(|e| PtError::Sftp(format!("seek remote: {e}")))?;
        }

        let mut buf = vec![0u8; CHUNK];
        let mut done = existing;
        progress(done, total);
        loop {
            let n = lf.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            rf.write_all(&buf[..n])
                .await
                .map_err(|e| PtError::Sftp(format!("write remote: {e}")))?;
            done += n as u64;
            progress(done, total);
        }
        rf.flush()
            .await
            .map_err(|e| PtError::Sftp(format!("flush remote: {e}")))?;
        Ok(done)
    }

    /// `mkdir -p`
    pub async fn mkdir_all(&self, path: &str) -> Result<()> {
        if path.is_empty() || path == "/" {
            return Ok(());
        }
        let mut cur = String::new();
        for part in path.split('/').filter(|p| !p.is_empty()) {
            cur.push('/');
            cur.push_str(part);
            if self.is_dir(&cur).await {
                continue;
            }
            match self.s.create_dir(cur.clone()).await {
                Ok(()) => {}
                Err(e) => {
                    // Race or already exists: accept if it is a directory now.
                    if !self.is_dir(&cur).await {
                        return Err(PtError::Sftp(format!("mkdir {cur}: {e}")));
                    }
                }
            }
        }
        Ok(())
    }

    /// Remove a file, or a directory tree when `recursive`.
    pub async fn remove(&self, path: &str, recursive: bool) -> Result<()> {
        let is_dir = self.is_dir(path).await;
        if !is_dir {
            return self
                .s
                .remove_file(path)
                .await
                .map_err(|e| PtError::Sftp(format!("rm {path}: {e}")));
        }
        if !recursive {
            return self
                .s
                .remove_dir(path)
                .await
                .map_err(|e| PtError::Sftp(format!("rmdir {path}: {e}")));
        }
        for e in self.list(path).await? {
            let child = format!("{}/{}", path.trim_end_matches('/'), e.name);
            Box::pin(self.remove(&child, true)).await?;
        }
        self.s
            .remove_dir(path)
            .await
            .map_err(|e| PtError::Sftp(format!("rmdir {path}: {e}")))
    }

    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.s
            .rename(from, to)
            .await
            .map_err(|e| PtError::Sftp(format!("rename {from} -> {to}: {e}")))
    }
}

/// Split `user@host:/path` into (host-spec, remote path).
pub fn split_remote_spec(spec: &str) -> Result<(&str, &str)> {
    match spec.split_once(':') {
        Some((host, path)) if !host.is_empty() => Ok((host, path)),
        _ => Err(PtError::Config(format!(
            "expected user@host:/path, got '{spec}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_remote_spec() {
        assert_eq!(
            split_remote_spec("alice@example.com:/var/log").unwrap(),
            ("alice@example.com", "/var/log")
        );
        assert!(split_remote_spec("example.com").is_err());
    }

    #[test]
    fn mode_string_renders() {
        let e = Entry {
            name: "x".into(),
            is_dir: true,
            is_symlink: false,
            size: 0,
            mode: Some(0o755),
            mtime: None,
        };
        assert_eq!(e.mode_string(), "drwxr-xr-x");
    }
}
