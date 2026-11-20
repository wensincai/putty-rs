//! Port forwarding: `-L` (local), `-D` (SOCKS5), and `-R` (remote).
//!
//! PuTTY implements this in `ssh/portfwd.c` with its own listener/plug
//! abstractions. Here each forward is a `TcpListener` plus a task per accepted
//! connection that pumps bytes between the socket and a `direct-tcpip` channel.
//!
//! Half-close matters: when the local side finishes sending, we send EOF on the
//! channel and keep reading, so protocols that shutdown one direction (HTTP/1.0,
//! `nc -N`) still work.

use crate::config::ForwardSpec;
use crate::error::{PtError, Result};
use crate::session::ClientHandler;
use russh::client::Handle;
use russh::ChannelMsg;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Bind a listener for a forward. `bind` may be a host name or an address.
pub async fn bind_local(bind: &str, port: u16) -> Result<TcpListener> {
    TcpListener::bind((bind, port))
        .await
        .map_err(|e| PtError::Forward(format!("cannot listen on {bind}:{port}: {e}")))
}

/// Accept connections forever, tunnelling each through the SSH session.
pub fn spawn_local_forward(
    handle: Arc<Handle<ClientHandler>>,
    listener: TcpListener,
    target: (String, u16),
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (socket, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "forward accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    continue;
                }
            };
            let handle = handle.clone();
            let (host, port) = target.clone();
            tokio::spawn(async move {
                let origin = peer.ip().to_string();
                let origin_port = peer.port() as u32;
                match handle
                    .channel_open_direct_tcpip(host.clone(), port as u32, origin, origin_port)
                    .await
                {
                    Ok(channel) => {
                        if let Err(e) = pump(channel, socket).await {
                            tracing::debug!(target = %format!("{host}:{port}"), error = %e, "forward connection ended");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(target = %format!("{host}:{port}"), error = %e, "direct-tcpip refused");
                    }
                }
            });
        }
    })
}

/// Minimal SOCKS5 server (CONNECT only, no UDP ASSOCIATE/BIND).
pub fn spawn_socks5(handle: Arc<Handle<ClientHandler>>, listener: TcpListener) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (socket, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    continue;
                }
            };
            let handle = handle.clone();
            tokio::spawn(async move {
                if let Err(e) = socks5_connection(handle, socket).await {
                    tracing::debug!(error = %e, "socks5 connection closed");
                }
            });
        }
    })
}

/// Accept a `-R` request. Not implemented: the transport crate does not expose
/// incoming `forwarded-tcpip` channels to clients yet.
pub async fn request_remote_forward(
    _handle: &Arc<Handle<ClientHandler>>,
    spec: &ForwardSpec,
) -> Result<()> {
    Err(PtError::Forward(format!(
        "remote forwarding ({}) is not supported by this build; \
         run a local forward from the remote side instead (pt -L ... on the server)",
        spec.describe()
    )))
}

async fn socks5_connection(handle: Arc<Handle<ClientHandler>>, mut socket: TcpStream) -> Result<()> {
    // greeting: VER NMETHODS METHODS...
    let mut head = [0u8; 2];
    socket.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(PtError::Forward("not SOCKS5".into()));
    }
    let mut methods = vec![0u8; head[1] as usize];
    socket.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        // username/password is accepted too, but we do not verify it.
        if methods.contains(&0x02) {
            socket.write_all(&[0x05, 0x02]).await?;
            let mut ver = [0u8; 2];
            socket.read_exact(&mut ver).await?;
            let mut ulen = [0u8; 1];
            socket.read_exact(&mut ulen).await?;
            let mut user = vec![0u8; ulen[0] as usize];
            socket.read_exact(&mut user).await?;
            let mut plen = [0u8; 1];
            socket.read_exact(&mut plen).await?;
            let mut _pass = vec![0u8; plen[0] as usize];
            socket.read_exact(&mut _pass).await?;
            socket.write_all(&[0x01, 0x00]).await?;
        } else {
            socket.write_all(&[0x05, 0xff]).await?;
            return Err(PtError::Forward("no acceptable SOCKS5 auth method".into()));
        }
    } else {
        socket.write_all(&[0x05, 0x00]).await?;
    }

    // request: VER CMD RSV ATYP ADDR PORT
    let mut req = [0u8; 4];
    socket.read_exact(&mut req).await?;
    if req[1] != 0x01 {
        socket.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err(PtError::Forward("only CONNECT is supported".into()));
    }
    let host = match req[3] {
        0x01 => {
            let mut b = [0u8; 4];
            socket.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        0x03 => {
            let mut l = [0u8; 1];
            socket.read_exact(&mut l).await?;
            let mut b = vec![0u8; l[0] as usize];
            socket.read_exact(&mut b).await?;
            String::from_utf8_lossy(&b).into_owned()
        }
        0x04 => {
            let mut b = [0u8; 16];
            socket.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        _ => {
            socket.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(PtError::Forward("bad address type".into()));
        }
    };
    let mut pb = [0u8; 2];
    socket.read_exact(&mut pb).await?;
    let port = u16::from_be_bytes(pb);

    match handle
        .channel_open_direct_tcpip(host.clone(), port as u32, "127.0.0.1", 0)
        .await
    {
        Ok(channel) => {
            socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            pump(channel, socket).await
        }
        Err(e) => {
            socket.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            Err(PtError::Forward(format!("direct-tcpip {host}:{port}: {e}")))
        }
    }
}

/// Bi-directional pump between a TCP socket and an SSH channel.
async fn pump(mut channel: russh::Channel<russh::client::Msg>, socket: TcpStream) -> Result<()> {
    let (mut rd, mut wr) = socket.into_split();
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        if wr.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Some(ChannelMsg::Eof) => {
                        let _ = wr.shutdown().await;
                    }
                    Some(ChannelMsg::Close) | None => break,
                    _ => {}
                }
            }
            r = rd.read(&mut buf) => {
                match r {
                    Ok(0) => {
                        let _ = channel.eof().await;
                    }
                    Ok(n) => {
                        if channel.data_bytes(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    let _ = channel.close().await;
    Ok(())
}

/// Startup helper used by the CLI: bind every forward and spawn its task.
pub async fn start_all(
    handle: &Arc<Handle<ClientHandler>>,
    specs: &[ForwardSpec],
) -> Result<Vec<(String, JoinHandle<()>)>> {
    let mut started = Vec::new();
    for spec in specs {
        match spec {
            ForwardSpec::Local { bind, bind_port, host, port } => {
                let listener = bind_local(bind, *bind_port).await?;
                let shown = format!("-L {bind}:{bind_port} -> {host}:{port}");
                let task = spawn_local_forward(handle.clone(), listener, (host.clone(), *port));
                tracing::info!(forward = %shown, "forward listening");
                started.push((shown, task));
            }
            ForwardSpec::Dynamic { bind, bind_port } => {
                let listener = bind_local(bind, *bind_port).await?;
                let shown = format!("-D {bind}:{bind_port} (SOCKS5)");
                let task = spawn_socks5(handle.clone(), listener);
                tracing::info!(forward = %shown, "forward listening");
                started.push((shown, task));
            }
            ForwardSpec::Remote { .. } => {
                request_remote_forward(handle, spec).await?;
            }
        }
    }
    Ok(started)
}

/// Convenience for tests: local address of a bound listener.
pub fn local_addr(l: &TcpListener) -> Option<SocketAddr> {
    l.local_addr().ok()
}
