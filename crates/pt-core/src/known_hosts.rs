//! OpenSSH `known_hosts` support: parsing, matching, appending, fingerprints.
//!
//! PuTTY keeps host keys in the registry (and offers `~/.putty/sshhostkeys`).
//! We use the OpenSSH text format instead so the same file can be shared with
//! `ssh`, `git` and `ssh-keyscan` — that also makes the trust decision
//! auditable by the user with familiar tools.
//!
//! Supported line forms:
//!
//! ```text
//! host[,host...] keytype base64key [comment]
//! [host]:port keytype base64key         # non-default port
//! *.example.com,!bad.example.com ...    # wildcards and negation
//! @cert-authority / @revoked            # markers (currently ignored)
//! |1|salt|hash ...                      # hashed host names (not matched)
//! ```

use crate::error::{PtError, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

/// Outcome of looking up a server key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Same key as recorded.
    Match,
    /// A key of this type is recorded, but it differs.
    Mismatch { recorded: String },
    /// No usable entry for this host.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct KnownHosts {
    path: PathBuf,
}

impl KnownHosts {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        KnownHosts { path: path.into() }
    }

    /// `~/.ssh/known_hosts` (created lazily on first append).
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".ssh")
            .join("known_hosts")
    }

    /// `$PT_KNOWN_HOSTS` if set (used by tests and portable installs),
    /// otherwise the OpenSSH default location.
    pub fn from_env_or_default() -> Self {
        match std::env::var_os("PT_KNOWN_HOSTS") {
            Some(p) => KnownHosts::new(PathBuf::from(p)),
            None => KnownHosts::new(Self::default_path()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Look `host` up. `key_type` is e.g. `ssh-ed25519`, `key_b64` the blob.
    pub fn check(&self, host: &str, port: u16, key_type: &str, key_b64: &str) -> Result<Verdict> {
        let file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Verdict::Unknown),
            Err(e) => return Err(PtError::Io(e)),
        };
        let mut found_same_type: Option<String> = None;
        for line in BufReader::new(file).lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some(entry) = HostEntry::parse(line) else { continue };
            if entry.marker.is_some() {
                // @cert-authority / @revoked: out of scope for now
                continue;
            }
            let Some(hosts) = &entry.hosts else { continue }; // hashed entry
            // OpenSSH semantics: a matching `!pattern` excludes the line.
            let mut matched = false;
            let mut excluded = false;
            for p in hosts {
                if p.matches(host, port) {
                    if p.negated {
                        excluded = true;
                    } else {
                        matched = true;
                    }
                }
            }
            if excluded || !matched {
                continue;
            }
            if entry.key_type == key_type {
                if entry.key_b64 == key_b64 {
                    return Ok(Verdict::Match);
                }
                found_same_type = Some(entry.key_b64.to_string());
            }
        }
        Ok(match found_same_type {
            Some(recorded) => Verdict::Mismatch { recorded },
            None => Verdict::Unknown,
        })
    }

    /// Append a trusted key. Creates the file (mode 0600 on Unix) if needed.
    pub fn append(&self, host: &str, port: u16, key_type: &str, key_b64: &str) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{} {} {}", host_field(host, port), key_type, key_b64)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

/// The `host` field for a given host/port pair.
pub fn host_field(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        // OpenSSH always brackets non-default ports, IPv6 or not.
        format!("[{host}]:{port}")
    }
}

/// SHA256 fingerprint in OpenSSH style: `SHA256:<base64-no-padding>`.
pub fn fingerprint_sha256(key_b64: &str) -> String {
    match B64.decode(key_b64.trim()) {
        Ok(blob) => {
            let digest = Sha256::digest(&blob);
            let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
            format!("SHA256:{b64}")
        }
        Err(_) => "SHA256:<invalid key blob>".to_string(),
    }
}

/// MD5 fingerprint in the legacy colon-hex form (PuTTY showed this for years).
pub fn fingerprint_md5(key_b64: &str) -> String {
    match B64.decode(key_b64.trim()) {
        Ok(blob) => md5_hex(&blob),
        Err(_) => "<invalid key blob>".to_string(),
    }
}

/// Minimal MD5 (only used for legacy fingerprint display, not for security).
fn md5_hex(data: &[u8]) -> String {
    // RFC 1321 implementation kept tiny on purpose.
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32)
        .collect();
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0) =
        (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
    for chunk in msg.chunks(64) {
        let m: Vec<u32> = chunk
            .chunks(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(k[i])
                    .wrapping_add(m[g])
                    .rotate_left(S[i]),
            );
            a = tmp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = String::with_capacity(47);
    for (i, byte) in [a0, b0, c0, d0]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .enumerate()
    {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// One parsed line.
struct HostEntry<'a> {
    marker: Option<&'a str>,
    /// `None` when the host field is hashed (`|1|...`).
    hosts: Option<Vec<HostPattern>>,
    key_type: &'a str,
    key_b64: &'a str,
}

impl<'a> HostEntry<'a> {
    fn parse(line: &'a str) -> Option<Self> {
        let mut fields = line.split_whitespace();
        let mut first = fields.next()?;
        let mut marker = None;
        if first.starts_with('@') {
            marker = Some(first);
            first = fields.next()?;
        }
        let key_type = fields.next()?;
        let key_b64 = fields.next()?;
        let hosts = if first.starts_with("|1|") || first.starts_with("|") {
            None
        } else {
            Some(first.split(',').filter_map(HostPattern::parse).collect())
        };
        Some(HostEntry { marker, hosts, key_type, key_b64 })
    }
}

#[derive(Debug, Clone)]
struct HostPattern {
    negated: bool,
    pattern: String,
    port_specific: bool,
}

impl HostPattern {
    fn parse(tok: &str) -> Option<Self> {
        let (negated, tok) = match tok.strip_prefix('!') {
            Some(t) => (true, t),
            None => (false, tok),
        };
        if tok.is_empty() {
            return None;
        }
        // `[host]:port` is port-specific; a bare host matches the default port only
        let (pattern, port_specific) = if let Some(rest) = tok.strip_prefix('[') {
            let (h, tail) = rest.split_once(']')?;
            let p = tail.strip_prefix(':')?;
            (format!("{h}\u{0}{p}"), true)
        } else {
            (tok.to_string(), false)
        };
        Some(HostPattern { negated, pattern, port_specific })
    }

    fn matches(&self, host: &str, port: u16) -> bool {
        let target = if self.port_specific {
            format!("{host}\u{0}{port}")
        } else if port == 22 {
            host.to_string()
        } else {
            // a bare pattern only covers the default port
            return false;
        };
        wildcard_match(&self.pattern, &target)
    }
}

/// `*` and `?` matching, case-insensitive (DNS convention).
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let t: Vec<char> = text.to_ascii_lowercase().chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Evaluate a policy decision, returning a human-readable rejection reason.
pub fn evaluate(
    policy: crate::config::HostKeyPolicy,
    verdict: &Verdict,
    host: &str,
    port: u16,
    fingerprint: &str,
) -> std::result::Result<bool, String> {
    use crate::config::HostKeyPolicy::*;
    let where_ = host_field(host, port);
    match (policy, verdict) {
        (Off, _) => Ok(true),
        (_, Verdict::Match) => Ok(true),
        (Strict, Verdict::Unknown) => Err(format!(
            "host key for {where_} is not in known_hosts (fingerprint {fingerprint}).\n\
             Add it with: ssh-keyscan -p {port} {host} >> ~/.ssh/known_hosts\n\
             or rerun with --host-key-policy accept-new"
        )),
        (AcceptNew, Verdict::Unknown) => Ok(true),
        (_, Verdict::Mismatch { recorded }) => Err(format!(
            "HOST KEY CHANGED for {where_}\n  recorded: {}\n  offered : {fingerprint}\n\
             This can indicate a man-in-the-middle attack. If the server was rekeyed, \
             remove its line from known_hosts and reconnect.",
            fingerprint_sha256(recorded)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_field_rules() {
        assert_eq!(host_field("example.com", 22), "example.com");
        assert_eq!(host_field("example.com", 2222), "[example.com]:2222");
        assert_eq!(host_field("::1", 2222), "[::1]:2222");
    }

    #[test]
    fn wildcards() {
        assert!(wildcard_match("*.example.com", "a.example.com"));
        assert!(wildcard_match("a?c", "abc"));
        assert!(!wildcard_match("a?c", "abbc"));
        assert!(wildcard_match("10.0.0.*", "10.0.0.7"));
    }

    #[test]
    fn check_match_unknown_mismatch() {
        let dir = std::env::temp_dir().join(format!("pt-kh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let kh = KnownHosts::new(dir.join("known_hosts"));

        assert_eq!(kh.check("host.example", 22, "ssh-ed25519", "AAAA").unwrap(), Verdict::Unknown);

        kh.append("host.example", 22, "ssh-ed25519", "AAAA").unwrap();
        assert_eq!(kh.check("host.example", 22, "ssh-ed25519", "AAAA").unwrap(), Verdict::Match);

        match kh.check("host.example", 22, "ssh-ed25519", "BBBB").unwrap() {
            Verdict::Mismatch { recorded } => assert_eq!(recorded, "AAAA"),
            other => panic!("expected mismatch, got {other:?}"),
        }

        // a different key type is not a mismatch, just unknown
        assert_eq!(kh.check("host.example", 22, "ssh-rsa", "AAAA").unwrap(), Verdict::Unknown);

        // non-default port must not match the bare entry
        assert_eq!(kh.check("host.example", 2222, "ssh-ed25519", "AAAA").unwrap(), Verdict::Unknown);
        kh.append("host.example", 2222, "ssh-ed25519", "AAAA").unwrap();
        assert_eq!(
            kh.check("host.example", 2222, "ssh-ed25519", "AAAA").unwrap(),
            Verdict::Match
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn negation_wins() {
        let dir = std::env::temp_dir().join(format!("pt-kh-neg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("known_hosts");
        std::fs::write(
            &path,
            "*.corp.example,!bad.corp.example ssh-ed25519 AAAA\n",
        )
        .unwrap();
        let kh = KnownHosts::new(&path);
        assert_eq!(kh.check("ok.corp.example", 22, "ssh-ed25519", "AAAA").unwrap(), Verdict::Match);
        assert_eq!(kh.check("bad.corp.example", 22, "ssh-ed25519", "AAAA").unwrap(), Verdict::Unknown);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fingerprint_of_known_blob() {
        // base64 of "abc"
        let fp = fingerprint_sha256("YWJj");
        assert!(fp.starts_with("SHA256:"));
        // sha256("abc") = ba7816bf... -> base64 no padding
        assert_eq!(fp, "SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0");
    }

    #[test]
    fn md5_known_vector() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        assert_eq!(md5_hex(b""), "d4:1d:8c:d9:8f:00:b2:04:e9:80:09:98:ec:f8:42:7e");
    }

    #[test]
    fn policy_messages() {
        use crate::config::HostKeyPolicy::*;
        let v = Verdict::Unknown;
        assert!(evaluate(AcceptNew, &v, "h", 22, "SHA256:x").unwrap());
        assert!(evaluate(Strict, &v, "h", 22, "SHA256:x").is_err());
        let m = Verdict::Mismatch { recorded: "AAAA".into() };
        assert!(evaluate(AcceptNew, &m, "h", 22, "SHA256:x").is_err());
        assert!(evaluate(Off, &m, "h", 22, "SHA256:x").unwrap());
    }
}
