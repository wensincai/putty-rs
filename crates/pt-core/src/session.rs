//! SSH session establishment: dial → host key check → authentication.
//!
//! This is the Rust counterpart of PuTTY's `ssh.c` + `common.c` +
//! `userauth2-client.c` orchestration, minus the protocol bits that `russh`
//! already owns. Everything the caller needs to make a trust decision is
//! surfaced (`HostKeyInfo`), and every failure is explained
//! ([`crate::error::PtError`]).

use crate::auth::{self, AuthReport};
use crate::config::{AuthMethod, HostKeyPolicy, SessionProfile};
use crate::error::{PtError, Result};
use crate::known_hosts::{self, KnownHosts, Verdict};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;

use russh::client::{self, Handle};
use russh::keys::PublicKeyOrCertificate;

/// How the host key was accepted, for logging and UI display.
#[derive(Debug, Clone)]
pub struct HostKeyInfo {
    pub key_type: String,
    pub fingerprint: String,
    /// `Some("added to known_hosts")` when TOFU appended the key.
    pub note: Option<String>,
}

pub struct ConnectOptions {
    pub profile: SessionProfile,
    pub host_key_policy: HostKeyPolicy,
    /// Password for password auth; `None` means "ask the prompt callback".
    pub password: Option<String>,
    /// Called lazily only if password auth is actually attempted.
    pub password_prompt: Option<Arc<dyn Fn() -> Option<String> + Send + Sync>>,
    pub key_passphrase: Option<String>,
    pub connect_timeout: Duration,
}

impl ConnectOptions {
    pub fn new(profile: SessionProfile) -> Self {
        ConnectOptions {
            profile,
            host_key_policy: HostKeyPolicy::default(),
            password: None,
            password_prompt: None,
            key_passphrase: None,
            connect_timeout: Duration::from_secs(20),
        }
    }
}

pub struct Connected {
    pub handle: Handle<ClientHandler>,
    pub host_key: HostKeyInfo,
    pub auth_report: AuthReport,
}

#[derive(Default)]
struct HostKeyState {
    info: Option<HostKeyInfo>,
    error: Option<String>,
}

/// Client handler that performs the known_hosts / TOFU policy check.
pub struct ClientHandler {
    policy: HostKeyPolicy,
    known: KnownHosts,
    host: String,
    port: u16,
    state: Arc<Mutex<HostKeyState>>,
}

impl ClientHandler {
    fn new(
        policy: HostKeyPolicy,
        known: KnownHosts,
        host: String,
        port: u16,
        state: Arc<Mutex<HostKeyState>>,
    ) -> Self {
        ClientHandler { policy, known, host, port, state }
    }
}

fn key_parts(k: &PublicKeyOrCertificate) -> (String, String) {
    let text = match k {
        PublicKeyOrCertificate::PublicKey { key, .. } => key.to_openssh().unwrap_or_default(),
        // Certificates are stringified in the same "type blob" shape.
        PublicKeyOrCertificate::Certificate(c) => c.to_openssh().unwrap_or_default(),
    };
    let mut it = text.split_whitespace();
    (
        it.next().unwrap_or("unknown").to_string(),
        it.next().unwrap_or_default().to_string(),
    )
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        let (key_type, key_b64) = key_parts(server_public_key);
        let fingerprint = known_hosts::fingerprint_sha256(&key_b64);

        let verdict = match self.known.check(&self.host, self.port, &key_type, &key_b64) {
            Ok(v) => v,
            Err(e) => {
                self.state.lock().unwrap().error = Some(format!("known_hosts: {e}"));
                return Ok(false);
            }
        };

        match known_hosts::evaluate(
            self.policy,
            &verdict,
            &self.host,
            self.port,
            &fingerprint,
        ) {
            Err(reason) => {
                self.state.lock().unwrap().error = Some(reason);
                Ok(false)
            }
            Ok(_) => {
                let mut note = None;
                if matches!(verdict, Verdict::Unknown) && self.policy == HostKeyPolicy::AcceptNew {
                    match self.known.append(&self.host, self.port, &key_type, &key_b64) {
                        Ok(()) => {
                            note = Some(format!("added to {}", self.known.path().display()));
                        }
                        Err(e) => {
                            // Do not fail the connection on a read-only home; warn instead.
                            tracing::warn!(error = %e, "could not append host key");
                            note = Some(format!("not saved: {e}"));
                        }
                    }
                }
                let mut st = self.state.lock().unwrap();
                st.info = Some(HostKeyInfo { key_type, fingerprint, note });
                Ok(true)
            }
        }
    }
}

/// Establish an authenticated SSH session.
pub async fn connect(opts: ConnectOptions) -> Result<Connected> {
    let profile = &opts.profile;
    if profile.host.trim().is_empty() {
        return Err(PtError::Config("host is empty".into()));
    }
    if profile.user.trim().is_empty() {
        return Err(PtError::Config("user is empty (use user@host)".into()));
    }

    let dial = crate::proxy::dial(
        profile.proxy.as_ref(),
        &profile.host,
        profile.port,
    );
    let stream = tokio::time::timeout(opts.connect_timeout, dial)
        .await
        .map_err(|_| {
            PtError::Connect(format!(
                "{}:{} timed out after {:?}",
                profile.host, profile.port, opts.connect_timeout
            ))
        })??;
    stream.set_nodelay(true).ok();
    tracing::debug!(host = %profile.host, port = profile.port, "tcp connected");

    let cfg = client::Config {
        nodelay: true,
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        inactivity_timeout: None,
        ..Default::default()
    };

    let shared = Arc::new(Mutex::new(HostKeyState::default()));
    let known = KnownHosts::from_env_or_default();
    let handler = ClientHandler::new(
        opts.host_key_policy,
        known,
        profile.host.clone(),
        profile.port,
        shared.clone(),
    );

    let mut handle = match client::connect_stream(Arc::new(cfg), stream, handler).await {
        Ok(h) => h,
        Err(e) => {
            let st = shared.lock().unwrap();
            if let Some(reason) = &st.error {
                return Err(PtError::HostKey(reason.clone()));
            }
            return Err(PtError::Protocol(format!("ssh handshake failed: {e}")));
        }
    };

    let host_key = shared
        .lock()
        .unwrap()
        .info
        .clone()
        .ok_or_else(|| PtError::Protocol("server did not present a host key".into()))?;
    tracing::info!(
        host = %profile.host,
        key_type = %host_key.key_type,
        fingerprint = %host_key.fingerprint,
        "host key accepted"
    );

    let mut report = AuthReport::default();
    authenticate(&mut handle, &opts, &mut report).await?;
    Ok(Connected { handle, host_key, auth_report: report })
}

async fn authenticate(
    handle: &mut Handle<ClientHandler>,
    opts: &ConnectOptions,
    report: &mut AuthReport,
) -> Result<()> {
    let profile = &opts.profile;
    let user = profile.user.clone();
    let mut asked_password = false;

    for method in &profile.auth.order {
        match method {
            AuthMethod::PublicKey => {
                let Some(path) = profile.auth.default_key() else {
                    report.record(AuthMethod::PublicKey, "no key found (~/.ssh/id_*)", false);
                    continue;
                };
                let key = match auth::load_key(&path, opts.key_passphrase.as_deref()) {
                    Ok(k) => k,
                    Err(e) => {
                        report.record(AuthMethod::PublicKey, format!("{}", e), false);
                        continue;
                    }
                };
                let hash = handle.best_supported_rsa_hash().await.ok().flatten().flatten();
                let key = auth::with_hash_alg(key, hash);
                let name = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                match handle.authenticate_publickey(user.clone(), key).await {
                    Ok(r) if r.success() => {
                        report.record(AuthMethod::PublicKey, format!("key {name}"), true);
                        return Ok(());
                    }
                    Ok(_) => report.record(AuthMethod::PublicKey, format!("key {name}: refused"), false),
                    Err(e) => report.record(AuthMethod::PublicKey, format!("key {name}: {e}"), false),
                }
            }
            AuthMethod::Agent => {
                match agent_auth(handle, &user).await {
                    Ok(Some(desc)) => {
                        report.record(AuthMethod::Agent, desc, true);
                        return Ok(());
                    }
                    Ok(None) => report.record(AuthMethod::Agent, "no usable identity", false),
                    Err(e) => report.record(AuthMethod::Agent, format!("{e}"), false),
                }
            }
            AuthMethod::Password => {
                let pw = match (&opts.password, &opts.password_prompt) {
                    (Some(p), _) => Some(p.clone()),
                    (None, Some(prompt)) if !asked_password => {
                        asked_password = true;
                        prompt().map(|p| p.to_string())
                    }
                    _ => None,
                };
                let Some(pw) = pw else {
                    report.record(AuthMethod::Password, "no password supplied", false);
                    continue;
                };
                match handle.authenticate_password(user.clone(), pw).await {
                    Ok(r) if r.success() => {
                        report.record(AuthMethod::Password, "accepted", true);
                        return Ok(());
                    }
                    Ok(_) => report.record(AuthMethod::Password, "server refused", false),
                    Err(e) => report.record(AuthMethod::Password, format!("{e}"), false),
                }
            }
            AuthMethod::KeyboardInteractive => {
                // russh requires a handler callback for each prompt; not wired yet.
                report.record(
                    AuthMethod::KeyboardInteractive,
                    "not implemented in this build",
                    false,
                );
            }
        }
    }

    Err(PtError::Auth(
        report.failure_message(&user, &profile.host),
    ))
}

/// Try every identity the agent offers. `Ok(None)` means "agent reachable but
/// no identity was accepted".
///
/// The loop is a macro because `AgentClient<S>` is generic over the transport
/// (Unix socket vs Windows named pipe / Pageant), and `authenticate_publickey_with`
/// needs the concrete type for its `Signer` bound.
macro_rules! agent_identities {
    ($handle:ident, $user:ident, $agent:ident) => {{
        let ids = $agent
            .request_identities()
            .await
            .map_err(|e| PtError::Auth(format!("ssh-agent list failed: {e}")))?;
        let mut accepted = None;
        for id in ids {
            // Certificate identities are skipped: they need the certificate
            // itself to be offered, which this build does not support yet.
            let russh::keys::agent::AgentIdentity::PublicKey { key, comment } = &id else {
                continue;
            };
            match $handle
                .authenticate_publickey_with($user.to_string(), key.clone(), None, &mut $agent)
                .await
            {
                Ok(r) if r.success() => {
                    accepted = Some(format!("agent identity {comment}"));
                    break;
                }
                Ok(_) => continue,
                Err(e) => return Err(PtError::Auth(format!("agent sign failed: {e}"))),
            }
        }
        Ok(accepted)
    }};
}

#[cfg(unix)]
async fn agent_auth(
    handle: &mut Handle<ClientHandler>,
    user: &str,
) -> Result<Option<String>> {
    use russh::keys::agent::client::AgentClient;
    let mut agent = AgentClient::connect_env()
        .await
        .map_err(|e| PtError::Auth(format!("ssh-agent unavailable: {e}")))?;
    agent_identities!(handle, user, agent)
}

#[cfg(windows)]
async fn agent_auth(
    handle: &mut Handle<ClientHandler>,
    user: &str,
) -> Result<Option<String>> {
    use russh::keys::agent::client::AgentClient;
    // Prefer the OpenSSH for Windows agent pipe, then Pageant.
    if let Ok(mut agent) =
        AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await
    {
        return agent_identities!(handle, user, agent);
    }
    match AgentClient::connect_pageant().await {
        Ok(mut agent) => agent_identities!(handle, user, agent),
        Err(e) => Err(PtError::Auth(format!(
            "no ssh-agent found (OpenSSH pipe or Pageant): {e}"
        ))),
    }
}

/// Convenience helper used by tests and the CLI banner.
pub fn describe_target(p: &SessionProfile) -> String {
    let mut s = p.target();
    if let Some(proxy) = &p.proxy {
        s.push_str(&format!(" via {}", proxy.label()));
    }
    s
}

/// Re-export so downstream crates do not need to name the russh type.
pub type ClientTcp = TcpStream;
