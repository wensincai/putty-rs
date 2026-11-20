//! `pt sftp ...` — scriptable SFTP client.
//!
//! Usage:
//! ```text
//! pt sftp ls   user@host:/path
//! pt sftp get  user@host:/path [local] [-r] [--resume]
//! pt sftp put  local user@host:/path [-r] [--resume]
//! pt sftp mkdir user@host:/path
//! pt sftp rm   user@host:/path [-r]
//! ```
//! Connection flags mirror `pt` (`-P`, `-i`, `--password`, `--proxy`, `-o`).

use clap::{ArgAction, Parser, Subcommand};
use pt_core::config::{HostKeyPolicy, ProxyConfig, SessionProfile};
use pt_core::sftp::{split_remote_spec, SftpClient};
use pt_core::{ConnectOptions, PtError, Result};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "pt sftp", about = "SFTP client (get/put/ls/mkdir/rm)", disable_help_subcommand = true)]
struct SftpCli {
    /// SSH port
    #[arg(short = 'P', long)]
    port: Option<u16>,

    /// Private key file
    #[arg(short = 'i', long)]
    key: Option<PathBuf>,

    /// Password
    #[arg(long = "password", visible_alias = "pw")]
    password: Option<String>,

    /// Proxy URL
    #[arg(long)]
    proxy: Option<String>,

    /// Host key policy: strict | accept-new | off
    #[arg(long, default_value = "accept-new")]
    host_key_policy: String,

    /// Verbose logging
    #[arg(short = 'v', long, action = ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// List a remote directory
    Ls { spec: String },
    /// Download a file or directory
    Get {
        spec: String,
        local: Option<PathBuf>,
        #[arg(short = 'r', long)]
        recursive: bool,
        #[arg(long)]
        resume: bool,
    },
    /// Upload a file or directory
    Put {
        local: PathBuf,
        spec: String,
        #[arg(short = 'r', long)]
        recursive: bool,
        #[arg(long)]
        resume: bool,
    },
    /// Create a remote directory (mkdir -p)
    Mkdir { spec: String },
    /// Remove a remote file or directory
    Rm {
        spec: String,
        #[arg(short = 'r', long)]
        recursive: bool,
    },
}

pub fn run(args: &[String], verbose_hint: u8) -> i32 {
    let cli = match SftpCli::try_parse_from(std::iter::once("pt sftp".to_string()).chain(args.iter().cloned())) {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return 2;
        }
    };
    let code = match execute(&cli) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("pt sftp: {e}");
            255
        }
    };
    let _ = verbose_hint;
    code
}

fn policy(s: &str) -> Result<HostKeyPolicy> {
    match s {
        "strict" | "yes" => Ok(HostKeyPolicy::Strict),
        "accept-new" => Ok(HostKeyPolicy::AcceptNew),
        "off" | "no" => Ok(HostKeyPolicy::Off),
        other => Err(PtError::Config(format!("unknown host key policy '{other}'"))),
    }
}

fn profile_for(spec: &str, cli: &SftpCli) -> Result<(SessionProfile, String)> {
    let (hostspec, path) = split_remote_spec(spec)?;
    let (user, host) = match hostspec.rsplit_once('@') {
        Some((u, h)) => (u.to_string(), h.to_string()),
        None => (
            std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "root".into()),
            hostspec.to_string(),
        ),
    };
    let (host, port) = match host.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| PtError::Config(format!("bad port '{p}'")))?,
        ),
        _ => (host, cli.port.unwrap_or(22)),
    };
    let mut profile = SessionProfile::new("sftp", &host, &user);
    profile.port = cli.port.unwrap_or(port);
    profile.auth.key_path = cli.key.clone();
    if let Some(p) = &cli.proxy {
        profile.proxy = Some(ProxyConfig::parse(p)?);
    }
    Ok((profile, path.to_string()))
}

fn execute(cli: &SftpCli) -> Result<()> {
    let (spec, _) = match &cli.cmd {
        Cmd::Ls { spec } => (spec.clone(), ()),
        Cmd::Get { spec, .. } => (spec.clone(), ()),
        Cmd::Put { spec, .. } => (spec.clone(), ()),
        Cmd::Mkdir { spec } => (spec.clone(), ()),
        Cmd::Rm { spec, .. } => (spec.clone(), ()),
    };
    let (profile, remote_path) = profile_for(&spec, cli)?;

    let policy = policy(&cli.host_key_policy)?;
    let password = cli
        .password
        .clone()
        .or_else(|| std::env::var("PT_PASSWORD").ok().filter(|p| !p.is_empty()));
    let mut opts = ConnectOptions::new(profile.clone());
    opts.host_key_policy = policy;
    opts.password = password;
    opts.password_prompt = Some(Arc::new({
        let user = profile.user.clone();
        let host = profile.host.clone();
        move || rpassword::prompt_password(format!("{user}@{host}'s password: ")).ok()
    }));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| PtError::Config(format!("tokio: {e}")))?;

    rt.block_on(async move {
        let mut connected = pt_core::connect(opts).await?;
        if let Some(note) = &connected.host_key.note {
            eprintln!(
                "Warning: Permanently added '{}' ({}) to known hosts [{}].",
                pt_core::known_hosts::host_field(&profile.host, profile.port),
                connected.host_key.key_type,
                note
            );
        }
        let sftp = SftpClient::open(&mut connected.handle).await?;
        match &cli.cmd {
            Cmd::Ls { .. } => cmd_ls(&sftp, &remote_path).await,
            Cmd::Get { local, recursive, resume, .. } => {
                let local = local.clone().unwrap_or_else(|| {
                    PathBuf::from(
                        Path::new(&remote_path)
                            .file_name()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "download".into()),
                    )
                });
                let mut p = Progress::new();
                get_path(&sftp, &remote_path, &local, *recursive, *resume, &mut p).await
            }
            Cmd::Put { local, recursive, resume, .. } => {
                let mut p = Progress::new();
                put_path(&sftp, local, &remote_path, *recursive, *resume, &mut p).await
            }
            Cmd::Mkdir { .. } => {
                sftp.mkdir_all(&remote_path).await?;
                eprintln!("created {remote_path}");
                Ok(())
            }
            Cmd::Rm { recursive, .. } => {
                sftp.remove(&remote_path, *recursive).await?;
                eprintln!("removed {remote_path}");
                Ok(())
            }
        }
    })
}

async fn cmd_ls(sftp: &SftpClient, path: &str) -> Result<()> {
    let entries = sftp.list(path).await?;
    println!("total {}", entries.len());
    for e in entries {
        println!(
            "{} {:>10}  {}",
            e.mode_string(),
            e.size,
            e.name
        );
    }
    Ok(())
}

struct Progress {
    last: std::time::Instant,
    enabled: bool,
}

impl Progress {
    fn new() -> Self {
        Progress { last: std::time::Instant::now(), enabled: std::io::stderr().is_terminal() }
    }

    fn update(&mut self, done: u64, total: u64) {
        if !self.enabled {
            return;
        }
        if self.last.elapsed() < std::time::Duration::from_millis(200) && done < total {
            return;
        }
        self.last = std::time::Instant::now();
        let pct = (done * 100).checked_div(total).unwrap_or(0);
        eprint!("\r  {done}/{total} bytes ({pct}%)   ");
        if done >= total {
            eprintln!();
        }
    }
}

async fn get_path(
    sftp: &SftpClient,
    remote: &str,
    local: &Path,
    recursive: bool,
    resume: bool,
    p: &mut Progress,
) -> Result<()> {
    if sftp.is_dir(remote).await {
        if !recursive {
            return Err(PtError::Sftp(format!(
                "{remote} is a directory (use -r)"
            )));
        }
        std::fs::create_dir_all(local)?;
        for e in sftp.list(remote).await? {
            let r = format!("{}/{}", remote.trim_end_matches('/'), e.name);
            let l = local.join(&e.name);
            Box::pin(get_path(sftp, &r, &l, true, resume, p)).await?;
        }
        return Ok(());
    }
    let n = sftp
        .get(remote, local, resume, |d, t| p.update(d, t))
        .await?;
    eprintln!("{} <- {remote} ({n} bytes)", local.display());
    Ok(())
}

async fn put_path(
    sftp: &SftpClient,
    local: &Path,
    remote: &str,
    recursive: bool,
    resume: bool,
    p: &mut Progress,
) -> Result<()> {
    let meta = std::fs::metadata(local)?;
    if meta.is_dir() {
        if !recursive {
            return Err(PtError::Config(format!(
                "{} is a directory (use -r)",
                local.display()
            )));
        }
        sftp.mkdir_all(remote).await?;
        for entry in std::fs::read_dir(local)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let r = format!("{}/{}", remote.trim_end_matches('/'), name);
            let l = entry.path();
            Box::pin(put_path(sftp, &l, &r, true, resume, p)).await?;
        }
        return Ok(());
    }
    let n = sftp
        .put(local, remote, resume, |d, t| p.update(d, t))
        .await?;
    eprintln!("{} -> {remote} ({n} bytes)", local.display());
    Ok(())
}
