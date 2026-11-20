//! Configuration model.
//!
//! PuTTY keeps 211 options in a flat `Conf` struct and saves them to the
//! registry or `~/.putty/sessions`. We keep a curated subset that covers the
//! SSH client workflow, and store it as JSON so it is diffable and portable.
//!
//! Precedence (highest first): explicit CLI flags > environment > session
//! profile > built-in defaults.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// How strictly to verify the server's host key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum HostKeyPolicy {
    /// Reject any host not present in known_hosts.
    Strict,
    /// Trust on first use: append the key after showing its fingerprint,
    /// but refuse a *changed* key.
    #[default]
    AcceptNew,
    /// Do not verify at all (explicit opt-in, e.g. throwaway containers).
    Off,
}

/// Ordered authentication preferences, matching OpenSSH naming.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMethod {
    PublicKey,
    Agent,
    Password,
    KeyboardInteractive,
}

impl AuthMethod {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "publickey" => AuthMethod::PublicKey,
            "agent" => AuthMethod::Agent,
            "password" => AuthMethod::Password,
            "keyboard-interactive" | "keyboardinteractive" => AuthMethod::KeyboardInteractive,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AuthMethod::PublicKey => "publickey",
            AuthMethod::Agent => "agent",
            AuthMethod::Password => "password",
            AuthMethod::KeyboardInteractive => "keyboard-interactive",
        }
    }
}

fn default_auth_order() -> Vec<AuthMethod> {
    vec![
        AuthMethod::PublicKey,
        AuthMethod::Agent,
        AuthMethod::Password,
        AuthMethod::KeyboardInteractive,
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_auth_order")]
    pub order: Vec<AuthMethod>,
    /// OpenSSH private key to offer. `None` means "look at ~/.ssh" (see [`AuthConfig::default_key`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<PathBuf>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig { order: default_auth_order(), key_path: None }
    }
}

impl AuthConfig {
    /// Conventional key locations in preference order.
    pub fn default_key(&self) -> Option<PathBuf> {
        if let Some(k) = &self.key_path {
            return Some(k.clone());
        }
        let home = dirs::home_dir()?;
        ["id_ed25519", "id_ecdsa", "id_rsa"]
            .iter()
            .map(|n| home.join(".ssh").join(n))
            .find(|p| p.exists())
    }
}

/// Which protocol the proxy speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyKind {
    Http,
    Socks5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass: Option<String>,
}

impl ProxyConfig {
    /// Parse `http://[user:pass@]host:port` or `socks5://...`.
    pub fn parse(s: &str) -> crate::Result<Self> {
        let (kind, rest) = match s.split_once("://") {
            Some(("http", r)) | Some(("https", r)) => (ProxyKind::Http, r),
            Some(("socks5", r)) | Some(("socks5h", r)) => (ProxyKind::Socks5, r),
            Some((other, _)) => {
                return Err(crate::PtError::Proxy(format!(
                    "unsupported proxy scheme '{other}' (use http:// or socks5://)"
                )))
            }
            None => (ProxyKind::Http, s),
        };
        // credentials are only recognised before the last '@' of the authority
        let (cred, hostport) = match rest.rsplit_once('@') {
            Some((c, h)) => (Some(c), h),
            None => (None, rest),
        };
        let (user, pass) = match cred {
            Some(c) => match c.split_once(':') {
                Some((u, p)) => (Some(u.to_string()), Some(p.to_string())),
                None => (Some(c.to_string()), None),
            },
            None => (None, None),
        };
        let (host, port) = split_host_port(hostport, kind == ProxyKind::Http, 8080, 1080)?;
        Ok(ProxyConfig { kind, host, port, user, pass })
    }

    pub fn label(&self) -> String {
        format!(
            "{}://{}:{}",
            match self.kind {
                ProxyKind::Http => "http",
                ProxyKind::Socks5 => "socks5",
            },
            self.host,
            self.port
        )
    }
}

/// Split `host:port`, `[v6]:port`, `host` (default port when missing).
pub(crate) fn split_host_port(
    s: &str,
    default_port_http: bool,
    http_default: u16,
    socks_default: u16,
) -> crate::Result<(String, u16)> {
    let def = if default_port_http { http_default } else { socks_default };
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| crate::PtError::Proxy(format!("bad IPv6 literal '{s}'")))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| crate::PtError::Proxy(format!("bad port '{p}'")))?,
            None => def,
        };
        return Ok((host.to_string(), port));
    }
    // bare IPv6 without brackets is ambiguous; require brackets
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && !p.is_empty() => {
            let port = p
                .parse::<u16>()
                .map_err(|_| crate::PtError::Proxy(format!("bad port '{p}'")))?;
            Ok((h.to_string(), port))
        }
        _ => Ok((s.to_string(), def)),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalPrefs {
    pub cols: u16,
    pub rows: u16,
    pub term: String,
    pub scrollback: usize,
    #[serde(default)]
    pub theme: String,
    #[serde(default = "default_font_size")]
    pub font_size: f32,
}

fn default_font_size() -> f32 {
    14.0
}

impl Default for TerminalPrefs {
    fn default() -> Self {
        TerminalPrefs {
            cols: 80,
            rows: 24,
            term: "xterm-256color".into(),
            scrollback: 2000,
            theme: "putty".into(),
            font_size: 14.0,
        }
    }
}

/// Port forwarding specification (`-L`/`-R`/`-D`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ForwardSpec {
    /// Local listen address → remote target seen by the server.
    Local { bind: String, bind_port: u16, host: String, port: u16 },
    /// Remote listen address → target reachable from the client.
    Remote { bind: String, bind_port: u16, host: String, port: u16 },
    /// SOCKS5 dynamic forwarding.
    Dynamic { bind: String, bind_port: u16 },
}

impl ForwardSpec {
    /// Parse the OpenSSH argument form.
    ///
    /// - `-L [bind:]port:host:hostport`
    /// - `-R [bind:]port:host:hostport`
    /// - `-D [bind:]port`
    pub fn parse(kind: char, spec: &str) -> crate::Result<Self> {
        let parts: Vec<&str> = spec.rsplitn(3, ':').collect(); // reversed
        match kind {
            'L' | 'R' => {
                if parts.len() != 3 {
                    return Err(crate::PtError::Forward(format!(
                        "expected [bind:]port:host:hostport, got '{spec}'"
                    )));
                }
                // rsplitn yields (hostport, host, bind_part) because it walks backwards
                let (hostport, host, bind_part) = (parts[0], parts[1], parts[2]);
                let (bind, bind_port) = split_bind(bind_part)?;
                let port = hostport
                    .parse::<u16>()
                    .map_err(|_| crate::PtError::Forward(format!("bad port '{hostport}'")))?;
                let spec = if kind == 'L' {
                    ForwardSpec::Local { bind, bind_port, host: host.to_string(), port }
                } else {
                    ForwardSpec::Remote { bind, bind_port, host: host.to_string(), port }
                };
                Ok(spec)
            }
            'D' => {
                let (bind, bind_port) = split_bind(spec)?;
                Ok(ForwardSpec::Dynamic { bind, bind_port })
            }
            other => Err(crate::PtError::Forward(format!("unknown forward kind '{other}'"))),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            ForwardSpec::Local { bind, bind_port, host, port } => {
                format!("-L {bind}:{bind_port} -> {host}:{port}")
            }
            ForwardSpec::Remote { bind, bind_port, host, port } => {
                format!("-R {bind}:{bind_port} -> {host}:{port}")
            }
            ForwardSpec::Dynamic { bind, bind_port } => format!("-D {bind}:{bind_port}"),
        }
    }
}

fn split_bind(bind_part: &str) -> crate::Result<(String, u16)> {
    // Forms: "port" | "bind:port" | "[v6]:port"
    if let Some(rest) = bind_part.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| crate::PtError::Forward(format!("bad bind address '{bind_part}'")))?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| crate::PtError::Forward(format!("missing port in '{bind_part}'")))?
            .parse::<u16>()
            .map_err(|_| crate::PtError::Forward(format!("bad bind port in '{bind_part}'")))?;
        return Ok((host.to_string(), port));
    }
    match bind_part.rsplit_once(':') {
        Some((b, p)) if !b.is_empty() => {
            let port = p
                .parse::<u16>()
                .map_err(|_| crate::PtError::Forward(format!("bad bind port '{p}'")))?;
            Ok((b.to_string(), port))
        }
        _ => {
            let port = bind_part
                .parse::<u16>()
                .map_err(|_| crate::PtError::Forward(format!("bad port '{bind_part}'")))?;
            Ok(("127.0.0.1".to_string(), port))
        }
    }
}

/// One saved session (PuTTY's "Saved Sessions").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionProfile {
    pub name: String,
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxyConfig>,
    #[serde(default)]
    pub terminal: TerminalPrefs,
    #[serde(default)]
    pub forwards: Vec<ForwardSpec>,
}

fn default_ssh_port() -> u16 {
    22
}

impl SessionProfile {
    pub fn new(name: &str, host: &str, user: &str) -> Self {
        SessionProfile {
            name: name.into(),
            host: host.into(),
            port: 22,
            user: user.into(),
            auth: AuthConfig::default(),
            proxy: None,
            terminal: TerminalPrefs::default(),
            forwards: Vec::new(),
        }
    }

    /// `user@host:port` for display and logging.
    pub fn target(&self) -> String {
        if self.port == 22 {
            format!("{}@{}", self.user, self.host)
        } else {
            format!("{}@{}:{}", self.user, self.host, self.port)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalPrefs {
    #[serde(default)]
    pub terminal: TerminalPrefs,
    #[serde(default = "default_true")]
    pub keepalive: bool,
    #[serde(default = "default_keepalive")]
    pub keepalive_secs: u64,
}

fn default_true() -> bool {
    true
}
fn default_keepalive() -> u64 {
    30
}

impl Default for GlobalPrefs {
    fn default() -> Self {
        GlobalPrefs {
            terminal: TerminalPrefs::default(),
            keepalive: true,
            keepalive_secs: 30,
        }
    }
}

/// The whole configuration file (`~/.pt-rs/sessions.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "config_version")]
    pub version: u32,
    #[serde(default)]
    pub defaults: GlobalPrefs,
    #[serde(default)]
    pub sessions: Vec<SessionProfile>,
}

fn config_version() -> u32 {
    1
}

impl Default for Config {
    fn default() -> Self {
        Config { version: 1, defaults: GlobalPrefs::default(), sessions: Vec::new() }
    }
}

impl Config {
    /// `~/.pt-rs/sessions.json`, or `%APPDATA%\pt-rs\sessions.json` on Windows.
    pub fn path() -> crate::Result<PathBuf> {
        let dir = dirs::config_dir()
            .or_else(dirs::home_dir)
            .ok_or_else(|| crate::PtError::Config("cannot determine config directory".into()))?;
        Ok(dir.join("pt-rs").join("sessions.json"))
    }

    pub fn load() -> crate::Result<Self> {
        let path = Self::path()?;
        match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s)
                .map_err(|e| crate::PtError::Config(format!("{}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(crate::PtError::Io(e)),
        }
    }

    pub fn save(&self) -> crate::Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| crate::PtError::Config(format!("serialise: {e}")))?;
        // atomic replace so a crash cannot truncate the config
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn session(&self, name: &str) -> Option<&SessionProfile> {
        self.sessions.iter().find(|s| s.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proxy_with_credentials() {
        let p = ProxyConfig::parse("http://alice:s3cret@proxy.local:3128").unwrap();
        assert_eq!(p.kind, ProxyKind::Http);
        assert_eq!(p.host, "proxy.local");
        assert_eq!(p.port, 3128);
        assert_eq!(p.user.as_deref(), Some("alice"));
        assert_eq!(p.pass.as_deref(), Some("s3cret"));
    }

    #[test]
    fn parse_proxy_defaults() {
        let p = ProxyConfig::parse("socks5://127.0.0.1").unwrap();
        assert_eq!(p.port, 1080);
        let p = ProxyConfig::parse("proxy.local").unwrap();
        assert_eq!(p.port, 8080);
    }

    #[test]
    fn parse_proxy_ipv6() {
        let p = ProxyConfig::parse("socks5://[::1]:9050").unwrap();
        assert_eq!(p.host, "::1");
        assert_eq!(p.port, 9050);
    }

    #[test]
    fn parse_forward_local() {
        let f = ForwardSpec::parse('L', "8080:db.internal:5432").unwrap();
        assert_eq!(
            f,
            ForwardSpec::Local {
                bind: "127.0.0.1".into(),
                bind_port: 8080,
                host: "db.internal".into(),
                port: 5432
            }
        );
    }

    #[test]
    fn parse_forward_bind_addr() {
        let f = ForwardSpec::parse('L', "0.0.0.0:8080:localhost:80").unwrap();
        assert_eq!(
            f,
            ForwardSpec::Local {
                bind: "0.0.0.0".into(),
                bind_port: 8080,
                host: "localhost".into(),
                port: 80
            }
        );
    }

    #[test]
    fn parse_forward_dynamic() {
        assert_eq!(
            ForwardSpec::parse('D', "1080").unwrap(),
            ForwardSpec::Dynamic { bind: "127.0.0.1".into(), bind_port: 1080 }
        );
    }

    #[test]
    fn auth_method_roundtrip() {
        for m in ["publickey", "agent", "password", "keyboard-interactive"] {
            assert_eq!(AuthMethod::parse(m).unwrap().as_str(), m);
        }
        assert!(AuthMethod::parse("gssapi").is_none());
    }
}
