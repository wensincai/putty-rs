//! Authentication orchestration.
//!
//! PuTTY's `userauth2-client.c` drives a list of methods and keeps retrying
//! until the server is satisfied or the list is exhausted. We do the same, but
//! collect a structured report so the CLI can explain *why* it failed instead
//! of a bare "access denied".

use crate::config::AuthMethod;
use crate::error::{PtError, Result};

/// One attempted method.
#[derive(Debug, Clone)]
pub struct Attempt {
    pub method: AuthMethod,
    /// Short human note, e.g. `key id_ed25519` or `server refused`.
    pub detail: String,
    pub ok: bool,
}

#[derive(Debug, Default, Clone)]
pub struct AuthReport {
    pub attempts: Vec<Attempt>,
}

impl AuthReport {
    pub fn record(&mut self, method: AuthMethod, detail: impl Into<String>, ok: bool) {
        self.attempts.push(Attempt { method, detail: detail.into(), ok });
    }

    pub fn success(&self) -> Option<AuthMethod> {
        self.attempts.iter().find(|a| a.ok).map(|a| a.method)
    }

    /// A multi-line explanation used when every method failed.
    pub fn failure_message(&self, user: &str, host: &str) -> String {
        let mut s = format!("no authentication method succeeded for {user}@{host}");
        for a in &self.attempts {
            s.push_str(&format!("\n  - {:<22} {}", a.method.as_str(), a.detail));
        }
        if self.attempts.is_empty() {
            s.push_str("\n  (no method was attempted: no key, no agent, no password)");
        }
        s
    }
}

/// Load an OpenSSH private key, turning library errors into a readable reason.
///
/// A missing file is not fatal — the caller simply skips publickey auth.
pub fn load_key(
    path: &std::path::Path,
    passphrase: Option<&str>,
) -> Result<russh::keys::PrivateKey> {
    if !path.exists() {
        return Err(PtError::Auth(format!("key file not found: {}", path.display())));
    }
    russh::keys::load_secret_key(path, passphrase)
        .map_err(|e| PtError::Auth(format!("cannot load {}: {e}", path.display())))
}

/// Wrap a private key for the RSA hash negotiation that modern servers require.
pub fn with_hash_alg(
    key: russh::keys::PrivateKey,
    hash: Option<russh::keys::HashAlg>,
) -> russh::keys::PrivateKeyWithHashAlg {
    russh::keys::PrivateKeyWithHashAlg::new(std::sync::Arc::new(key), hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_summary_lists_attempts() {
        let mut r = AuthReport::default();
        r.record(AuthMethod::PublicKey, "key id_ed25519: refused", false);
        r.record(AuthMethod::Password, "server refused", false);
        let msg = r.failure_message("alice", "host");
        assert!(msg.contains("publickey"));
        assert!(msg.contains("password"));
        assert!(msg.contains("alice@host"));
        assert!(r.success().is_none());
    }

    #[test]
    fn missing_key_is_reported_not_panicking() {
        let e = load_key(std::path::Path::new("definitely-not-here"), None).unwrap_err();
        assert!(matches!(e, PtError::Auth(_)));
    }
}
