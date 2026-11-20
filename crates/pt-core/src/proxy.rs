//! CONNECT-style dialers for reaching the SSH server through a proxy.
//!
//! PuTTY's `proxy/` directory implements HTTP CONNECT, SOCKS 4/5, telnet and
//! "local command" proxies. We implement the two that matter today: HTTP
//! CONNECT (RFC 7231 §4.3.6) and SOCKS5 (RFC 1928) with optional
//! username/password auth (RFC 1929).

use crate::config::{ProxyConfig, ProxyKind};
use crate::error::{PtError, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Open a TCP connection to `host:port`, tunnelling through `cfg` if present.
pub async fn dial(cfg: Option<&ProxyConfig>, host: &str, port: u16) -> Result<TcpStream> {
    match cfg {
        None => TcpStream::connect((host, port))
            .await
            .map_err(|e| PtError::Connect(format!("{host}:{port}: {e}"))),
        Some(p) => {
            let mut tcp = TcpStream::connect((p.host.as_str(), p.port))
                .await
                .map_err(|e| {
                    PtError::Proxy(format!("cannot reach proxy {}: {e}", p.label()))
                })?;
            tcp.set_nodelay(true).ok();
            match p.kind {
                ProxyKind::Http => http_connect(&mut tcp, p, host, port).await?,
                ProxyKind::Socks5 => socks5(&mut tcp, p, host, port).await?,
            }
            Ok(tcp)
        }
    }
}

async fn http_connect(
    tcp: &mut TcpStream,
    cfg: &ProxyConfig,
    host: &str,
    port: u16,
) -> Result<()> {
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut req = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n"
    );
    if let Some(user) = &cfg.user {
        let cred = format!("{}:{}", user, cfg.pass.as_deref().unwrap_or(""));
        req.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64_standard(cred.as_bytes())
        ));
    }
    req.push_str("\r\n");
    tcp.write_all(req.as_bytes()).await?;
    tcp.flush().await?;

    // read the status line + headers (bounded)
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let n = tcp.read(&mut byte).await?;
        if n == 0 {
            return Err(PtError::Proxy("proxy closed the connection during CONNECT".into()));
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(PtError::Proxy("proxy response headers too large".into()));
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status = head.lines().next().unwrap_or("");
    let code = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    match code {
        200..=299 => Ok(()),
        407 => Err(PtError::Proxy(
            "proxy requires authentication (407); pass credentials as http://user:pass@host:port"
                .into(),
        )),
        _ => Err(PtError::Proxy(format!(
            "CONNECT {authority} rejected: {status}"
        ))),
    }
}

async fn socks5(tcp: &mut TcpStream, cfg: &ProxyConfig, host: &str, port: u16) -> Result<()> {
    let want_auth = cfg.user.is_some();
    // greeting: VER=5, NMETHODS, METHODS
    let greeting: &[u8] = if want_auth {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    tcp.write_all(greeting).await?;
    let mut resp = [0u8; 2];
    tcp.read_exact(&mut resp).await?;
    if resp[0] != 0x05 {
        return Err(PtError::Proxy(format!("not a SOCKS5 proxy (ver {})", resp[0])));
    }
    match resp[1] {
        0x00 => {}
        0x02 => {
            let user = cfg.user.as_deref().unwrap_or("");
            let pass = cfg.pass.as_deref().unwrap_or("");
            let mut msg = vec![0x01, user.len() as u8];
            msg.extend_from_slice(user.as_bytes());
            msg.push(pass.len() as u8);
            msg.extend_from_slice(pass.as_bytes());
            tcp.write_all(&msg).await?;
            let mut r = [0u8; 2];
            tcp.read_exact(&mut r).await?;
            if r[1] != 0x00 {
                return Err(PtError::Proxy("SOCKS5 authentication rejected".into()));
            }
        }
        0xFF => {
            return Err(PtError::Proxy(
                "SOCKS5 proxy accepted none of our auth methods".into(),
            ))
        }
        m => return Err(PtError::Proxy(format!("SOCKS5 unsupported auth method {m}"))),
    }

    // CONNECT request
    let mut req = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&ip.octets());
    } else {
        let bytes = host.as_bytes();
        if bytes.len() > 255 {
            return Err(PtError::Proxy("host name too long for SOCKS5".into()));
        }
        req.push(0x03);
        req.push(bytes.len() as u8);
        req.extend_from_slice(bytes);
    }
    req.extend_from_slice(&port.to_be_bytes());
    tcp.write_all(&req).await?;

    let mut head = [0u8; 4];
    tcp.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(PtError::Proxy("malformed SOCKS5 reply".into()));
    }
    if head[1] != 0x00 {
        let reason = match head[1] {
            0x01 => "general failure",
            0x02 => "connection not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        };
        return Err(PtError::Proxy(format!("SOCKS5 CONNECT failed: {reason}")));
    }
    // drain the bound address
    match head[3] {
        0x01 => {
            let mut skip = [0u8; 4 + 2];
            tcp.read_exact(&mut skip).await?;
        }
        0x04 => {
            let mut skip = [0u8; 16 + 2];
            tcp.read_exact(&mut skip).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len).await?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            tcp.read_exact(&mut skip).await?;
        }
        t => return Err(PtError::Proxy(format!("SOCKS5 bad address type {t}"))),
    }
    Ok(())
}

fn base64_standard(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_greeting_shapes() {
        // no-auth greeting is 3 bytes, auth greeting advertises both methods
        let no_auth = [0x05u8, 0x01, 0x00];
        assert_eq!(no_auth.len(), 3);
        let auth = [0x05u8, 0x02, 0x00, 0x02];
        assert_eq!(auth[1], 2);
    }

    #[test]
    fn base64_basic_credential() {
        assert_eq!(base64_standard(b"alice:secret"), "YWxpY2U6c2VjcmV0");
    }
}
