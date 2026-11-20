//! `pt` — command-line SSH client, the Rust counterpart of PuTTY's `plink`.
//!
//! Two modes:
//! * `pt [opts] user@host -- command ...`  → exec, exit status preserved
//! * `pt [opts] user@host`                 → interactive shell (PTY when a TTY)
//!
//! The CLI owns prompting and rendering; protocol work lives in `pt-core`.

use clap::{ArgAction, Parser};
use pt_core::config::{AuthMethod, HostKeyPolicy, ProxyConfig, SessionProfile};
use pt_core::exec::{exec, ExecChunk};
use pt_core::shell::{run_shell, InputMsg, ShellOptions};
use pt_core::{ConnectOptions, PtError, Result};
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "pt",
    version,
    about = "SSH client — Rust rewrite of PuTTY's plink",
    long_about = None,
    disable_help_subcommand = true
)]
struct Cli {
    /// Destination: [user@]host[:port]
    #[arg(value_name = "[USER@]HOST")]
    target: Option<String>,

    /// SSH port
    #[arg(short = 'P', long)]
    port: Option<u16>,

    /// Login user (overrides user@host)
    #[arg(short = 'l', long)]
    user: Option<String>,

    /// Private key file
    #[arg(short = 'i', long)]
    key: Option<PathBuf>,

    /// Password (prefer $PT_PASSWORD or the prompt; appears in shell history)
    #[arg(long = "password", visible_alias = "pw")]
    password: Option<String>,

    /// Proxy: http://[user:pass@]host:port or socks5://...
    #[arg(long)]
    proxy: Option<String>,

    /// OpenSSH-style option, e.g. -o StrictHostKeyChecking=no
    #[arg(short = 'o', long = "option", value_name = "KEY=VALUE")]
    options: Vec<String>,

    /// Host key policy: strict | accept-new | off
    #[arg(long, default_value = "accept-new")]
    host_key_policy: String,

    /// Verbose logging (-v, -vv)
    #[arg(short = 'v', long, action = ArgAction::Count)]
    verbose: u8,

    /// Never prompt for anything
    #[arg(long)]
    batch: bool,

    /// Do not request a PTY (ssh -T)
    #[arg(short = 'T', long = "no-pty")]
    no_pty: bool,

    /// Request a PTY even when stdin is not a terminal (for scripted tests)
    #[arg(long = "force-pty")]
    force_pty: bool,

    /// Do not start a shell (ssh -N), for forwarding only
    #[arg(short = 'N', long = "no-shell")]
    no_shell: bool,

    /// $TERM value
    #[arg(long)]
    term: Option<String>,

    /// Remote terminal columns
    #[arg(long)]
    cols: Option<u16>,

    /// Remote terminal rows
    #[arg(long)]
    rows: Option<u16>,

    /// Local forward [bind:]port:host:hostport
    #[arg(short = 'L', value_name = "SPEC")]
    local: Vec<String>,

    /// Remote forward [bind:]port:host:hostport
    #[arg(short = 'R', value_name = "SPEC")]
    remote: Vec<String>,

    /// Dynamic (SOCKS5) forward [bind:]port
    #[arg(short = 'D', value_name = "SPEC")]
    dynamic: Vec<String>,

    /// Remote command; everything after the destination
    #[arg(value_name = "COMMAND", trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

mod sftp_cli;

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    // `pt sftp ...` is dispatched before clap so it can keep its own flags.
    if argv.get(1).map(|s| s.as_str()) == Some("sftp") {
        let verbose = argv.iter().filter(|a| *a == "-v").count() as u8;
        init_tracing(verbose);
        std::process::exit(sftp_cli::run(&argv[2..], verbose));
    }
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let code = match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("pt: {e}");
            255
        }
    };
    std::process::exit(code);
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "debug",
        _ => "trace",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(format!("{level},russh={level}")));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

fn parse_destination(cli: &Cli) -> Result<SessionProfile> {
    let raw = cli
        .target
        .as_deref()
        .ok_or_else(|| PtError::Config("no destination given (use [user@]host)".into()))?;
    let (user_part, host_part) = match raw.rsplit_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string()),
        None => (None, raw.to_string()),
    };
    // host[:port], with [v6]:port support
    let (host, port_in_target) = if let Some(rest) = host_part.strip_prefix('[') {
        let (h, tail) = rest
            .split_once(']')
            .ok_or_else(|| PtError::Config(format!("bad IPv6 literal '{raw}'")))?;
        let p = tail.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
        (h.to_string(), p)
    } else if host_part.matches(':').count() == 1 {
        let (h, p) = host_part.rsplit_once(':').unwrap();
        (h.to_string(), p.parse::<u16>().ok())
    } else {
        (host_part, None)
    };
    if host.is_empty() {
        return Err(PtError::Config("empty host".into()));
    }

    let user = cli
        .user
        .clone()
        .or(user_part)
        .or_else(|| std::env::var("USER").ok())
        .or_else(|| std::env::var("USERNAME").ok())
        .ok_or_else(|| PtError::Config("no user given (use user@host or -l)".into()))?;

    let mut profile = SessionProfile::new("cli", &host, &user);
    profile.port = cli.port.or(port_in_target).unwrap_or(22);
    profile.auth.key_path = cli.key.clone();

    if let Some(p) = &cli.proxy {
        profile.proxy = Some(ProxyConfig::parse(p)?);
    }
    for spec in &cli.local {
        profile.forwards.push(pt_core::ForwardSpec::parse('L', spec)?);
    }
    for spec in &cli.remote {
        profile.forwards.push(pt_core::ForwardSpec::parse('R', spec)?);
    }
    for spec in &cli.dynamic {
        profile.forwards.push(pt_core::ForwardSpec::parse('D', spec)?);
    }
    Ok(profile)
}

/// Apply `-o KEY=VALUE` options, mirroring the OpenSSH names users know.
fn apply_options(cli: &Cli, profile: &mut SessionProfile) -> Result<HostKeyPolicy> {
    let mut policy = match cli.host_key_policy.as_str() {
        "strict" | "yes" => HostKeyPolicy::Strict,
        "accept-new" => HostKeyPolicy::AcceptNew,
        "off" | "no" => HostKeyPolicy::Off,
        other => {
            return Err(PtError::Config(format!(
                "unknown --host-key-policy '{other}' (strict|accept-new|off)"
            )))
        }
    };
    let mut order: Option<Vec<AuthMethod>> = None;
    for opt in &cli.options {
        let (k, v) = opt
            .split_once('=')
            .ok_or_else(|| PtError::Config(format!("-o expects KEY=VALUE, got '{opt}'")))?;
        match k.trim().to_ascii_lowercase().as_str() {
            "stricthostkeychecking" => {
                policy = match v.trim().to_ascii_lowercase().as_str() {
                    "yes" | "true" => HostKeyPolicy::Strict,
                    "no" | "false" => HostKeyPolicy::Off,
                    "accept-new" => HostKeyPolicy::AcceptNew,
                    other => {
                        return Err(PtError::Config(format!("bad StrictHostKeyChecking '{other}'")))
                    }
                };
            }
            "userknownhostsfile" => {
                // Read by KnownHosts::from_env_or_default()
                std::env::set_var("PT_KNOWN_HOSTS", v);
            }
            "identityfile" => profile.auth.key_path = Some(PathBuf::from(v)),
            "preferredauthentications" => {
                let methods: Vec<AuthMethod> =
                    v.split(',').filter_map(AuthMethod::parse).collect();
                if methods.is_empty() {
                    return Err(PtError::Config(format!(
                        "no usable method in PreferredAuthentications='{v}'"
                    )));
                }
                order = Some(methods);
            }
            "port" => {
                profile.port = v
                    .parse()
                    .map_err(|_| PtError::Config(format!("bad Port '{v}'")))?
            }
            // Accepted for compatibility; keepalive defaults already apply.
            "connecttimeout" | "serveraliveinterval" | "serveralivecountmax" => {}
            other => eprintln!("pt: warning: ignoring unsupported option '{other}'"),
        }
    }
    if let Some(o) = order {
        profile.auth.order = o;
    }
    Ok(policy)
}

fn password_from_env() -> Option<String> {
    std::env::var("PT_PASSWORD").ok().filter(|p| !p.is_empty())
}

fn run(cli: Cli) -> Result<i32> {
    if cli.verbose > 0 {
        eprintln!("pt {} (PuTTY 0.85 rewrite)", env!("CARGO_PKG_VERSION"));
    }

    let mut profile = parse_destination(&cli)?;
    let policy = apply_options(&cli, &mut profile)?;

    if !cli.batch {
        eprintln!(
            "connecting to {} (host key policy: {:?})",
            pt_core::session::describe_target(&profile),
            policy
        );
    }

    let password = cli.password.clone().or_else(password_from_env);
    let prompt_password: Option<Arc<dyn Fn() -> Option<String> + Send + Sync>> =
        if cli.batch || password.is_some() {
            None
        } else {
            let user = profile.user.clone();
            let host = profile.host.clone();
            Some(Arc::new(move || {
                let prompt = format!("{user}@{host}'s password: ");
                rpassword::prompt_password(prompt).ok()
            }))
        };

    let mut opts = ConnectOptions::new(profile.clone());
    opts.host_key_policy = policy;
    opts.password = password;
    opts.password_prompt = prompt_password;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| PtError::Config(format!("tokio runtime: {e}")))?;

    rt.block_on(async move {
        let connected = pt_core::connect(opts).await?;
        let handle = std::sync::Arc::new(connected.handle);

        // TOFU notice, in OpenSSH's wording so it is recognisable.
        if let Some(note) = &connected.host_key.note {
            eprintln!(
                "Warning: Permanently added '{}' ({}) to the list of known hosts [{}].",
                pt_core::known_hosts::host_field(&profile.host, profile.port),
                connected.host_key.key_type,
                note
            );
        }
        tracing::info!(
            fingerprint = %connected.host_key.fingerprint,
            auth = ?connected.auth_report.success(),
            "authenticated"
        );

        let mut _forwards = Vec::new();
        if !profile.forwards.is_empty() {
            _forwards = pt_core::forward::start_all(&handle, &profile.forwards).await?;
            for (desc, _) in &_forwards {
                eprintln!("pt: listening: {desc}");
            }
        }

        let code;
        if cli.command.is_empty() {
            if cli.no_shell {
                eprintln!("pt: session open; press Ctrl-C to close");
                tokio::signal::ctrl_c().await.ok();
                code = 0;
            } else {
                code = run_interactive(&handle, &cli).await?;
            }
        } else {
            let cmd = cli.command.join(" ");
            let status = exec(&handle, &cmd, |chunk| match chunk {
                ExecChunk::Stdout(d) => {
                    let _ = std::io::stdout().write_all(&d);
                    let _ = std::io::stdout().flush();
                }
                ExecChunk::Stderr(d) => {
                    let _ = std::io::stderr().write_all(&d);
                    let _ = std::io::stderr().flush();
                }
            })
            .await?;
            code = status.unwrap_or(0) as i32;
        }
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        Ok(code)
    })
}

async fn run_interactive(
    handle: &std::sync::Arc<russh::client::Handle<pt_core::session::ClientHandler>>,
    cli: &Cli,
) -> Result<i32> {
    let stdin_is_tty = std::io::stdin().is_terminal();
    let want_pty = !cli.no_pty && (stdin_is_tty || cli.force_pty);

    // A missing PTY is silent in OpenSSH too, but there it is never a surprise:
    // users reach it via `ssh -T`. Here it usually means the terminal emulator
    // gave us a pipe (mintty, some launchers), and the symptoms downstream are
    // confusing (no Tab completion, vim cannot switch modes), so say something.
    if !cli.no_pty && !stdin_is_tty && !cli.force_pty {
        eprintln!(
            "pt: warning: stdin is not a terminal, so NO PTY will be requested (like `ssh -T`)."
        );
        eprintln!("    Expect: no Tab completion, vi/less/htop cannot control the screen,");
        eprintln!("    and remote lines are only echoed after Enter.");
        eprintln!("    Fix: run pt from a real console (Windows Terminal / cmd / PowerShell),");
        eprintln!("    or pass --force-pty to request one anyway; you can check with `tty` in the session.");
    }

    let (cols, rows) = match crossterm::terminal::size() {
        Ok((c, r)) if want_pty => (c, r),
        _ => (cli.cols.unwrap_or(80), cli.rows.unwrap_or(24)),
    };

    let shell_opts = ShellOptions {
        term: cli.term.clone().unwrap_or_else(|| "xterm-256color".into()),
        cols,
        rows,
        want_pty,
    };
    tracing::debug!(pty = want_pty, cols, rows, term = %shell_opts.term, "starting shell");

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<InputMsg>();

    // stdin reader: raw bytes, so every key (including Ctrl-C) reaches the server
    let tx_stdin = tx.clone();
    let raw_guard = if want_pty {
        // If raw mode fails we must say so: in cooked mode the Windows console
        // line editor eats Tab and turns Esc into "clear the input line", which
        // looks exactly like "those keys do nothing" while plain commands work.
        match crossterm::terminal::enable_raw_mode() {
            Ok(()) => Some(RawGuard),
            Err(e) => {
                eprintln!(
                    "pt: warning: cannot enable raw terminal mode ({e}); \
                     Tab/Esc/arrow keys will be handled by the local console line editor \
                     and may never reach the remote shell."
                );
                None
            }
        }
    } else {
        None
    };
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    let _ = tx_stdin.send(InputMsg::Eof);
                    break;
                }
                Ok(n) => {
                    if tx_stdin.send(InputMsg::Data(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // resize watcher
    if want_pty {
        let tx_resize = tx.clone();
        std::thread::spawn(move || {
            let mut last = (cols, rows);
            loop {
                std::thread::sleep(std::time::Duration::from_millis(250));
                if let Ok(size) = crossterm::terminal::size() {
                    if size != last {
                        last = size;
                        if tx_resize
                            .send(InputMsg::Resize { cols: size.0, rows: size.1 })
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });
    }
    drop(tx);

    let mut stdout = std::io::stdout();
    let result = run_shell(handle, &shell_opts, rx, |chunk| match chunk {
        pt_core::shell::ShellChunk::Stdout(d) | pt_core::shell::ShellChunk::Stderr(d) => {
            let _ = stdout.write_all(&d);
            let _ = stdout.flush();
        }
    })
    .await;
    drop(raw_guard);
    Ok(result?.unwrap_or(0) as i32)
}

/// Restores cooked mode even on early return / panic unwinding.
struct RawGuard;

impl Drop for RawGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
        let mut out = std::io::stdout();
        let _ = out.write_all(b"\r\n");
        let _ = out.flush();
    }
}
