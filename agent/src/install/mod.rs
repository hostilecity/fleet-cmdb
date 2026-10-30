//! `fleet-agent install` and `fleet-agent uninstall` (P1-A10, FR-S.5, ADR 0017).
//!
//! `sudo fleet-agent install --server https://agent.example.lan` runs four steps, each printing what it
//! did and, on failure, what happened and what to do next:
//!
//! 1. **Preflight** ([`preflight`]): root, Debian 13 on x86_64 (DEC-01), systemd, every existing path the
//!    installer would touch is safe (no symlinks, owned by root, not writable by others), and the
//!    server is the agent API and has a certificate this VM trusts. Nothing is changed before this
//!    passes.
//! 2. **Install the binary** ([`layout`]) into the side-by-side layout (P1-PACKAGING, ADR 0018) and write
//!    the systemd unit built into the binary.
//! 3. **Enroll** ([`enroll`]): by onboarding (the default; an operator approves the request in the
//!    dashboard) or with a pre-registered one-time token. The config with the credential is written
//!    atomically, mode `0600`, only once the credential has been received. A re-run on an enrolled VM
//!    keeps the credential.
//! 4. **Start**: a heartbeat with the new config confirms the server accepts the credential, then the
//!    unit is enabled and (re)started, and the installer waits until the service is running.
//!
//! Every step is idempotent, so re-running the same command repairs or upgrades an installation (the
//! manual upgrade, NFR-4). `uninstall` ([`uninstall`]) removes what `install` created.
//!
//! Everything works on a [`Host`] whose paths are under a root directory and whose systemd and clock are
//! traits, so the whole flow is tested without root against a local TLS server.

mod configfile;
mod enroll;
mod fsx;
mod layout;
mod preflight;
mod qr;
mod systemd;
mod token;
mod ui;
mod uninstall;

#[cfg(test)]
mod tests;

use std::fmt;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::AGENT_VERSION;
use crate::config::Config;
use crate::shutdown::Shutdown;

pub use systemd::{Systemctl, Systemd};
pub use token::TokenSource;
pub use ui::{Mode, Ui};

/// How an install or uninstall ended (the process exit status). Documented in `agent/README.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// 1: a step failed on this VM (a file could not be written, the service did not start).
    Failed,
    /// 2: the command line or the token given is wrong.
    Usage,
    /// 3: a preflight check failed; nothing was changed.
    Preflight,
    /// 4: an operator rejected the onboarding request, or the server rejected this VM's credential.
    Rejected,
    /// 5: the onboarding request expired, or the enrollment token is invalid, expired, or used.
    Expired,
    /// 6: the server failed or could not be reached during enrollment or confirmation.
    Server,
    /// 130: interrupted (Ctrl-C or SIGTERM) before finishing.
    Interrupted,
}

impl Failure {
    pub fn code(self) -> u8 {
        match self {
            Self::Failed => 1,
            Self::Usage => 2,
            Self::Preflight => 3,
            Self::Rejected => 4,
            Self::Expired => 5,
            Self::Server => 6,
            Self::Interrupted => 130,
        }
    }

    /// The name used in `--json` output.
    pub fn kind(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Usage => "usage",
            Self::Preflight => "preflight_failed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Server => "server_error",
            Self::Interrupted => "interrupted",
        }
    }
}

/// A failure, with what happened and what to do next. Never contains a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallError {
    pub failure: Failure,
    pub what: String,
    pub next: String,
}

impl InstallError {
    pub fn new(failure: Failure, what: impl Into<String>, next: impl Into<String>) -> Self {
        Self {
            failure,
            what: what.into(),
            next: next.into(),
        }
    }

    /// A step on this VM failed (exit 1); re-running is safe.
    fn failed(what: impl Into<String>) -> Self {
        Self::new(
            Failure::Failed,
            what,
            "Fix the cause, then run the same command again; it continues safely from where it stopped.",
        )
    }
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} Next: {}", self.what, self.next)
    }
}

/// Where everything is installed, under `root` (`/` in production, a temporary directory in tests).
/// The layout is defined in P1-PACKAGING and ADR 0018.
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    fn at(&self, path: &str) -> PathBuf {
        self.root.join(path.trim_start_matches('/'))
    }
    pub fn lib_dir(&self) -> PathBuf {
        self.at("/usr/lib/fleet-agent")
    }
    pub fn versions_dir(&self) -> PathBuf {
        self.lib_dir().join("versions")
    }
    pub fn current(&self) -> PathBuf {
        self.lib_dir().join("current")
    }
    pub fn previous(&self) -> PathBuf {
        self.lib_dir().join("previous")
    }
    pub fn bin_link(&self) -> PathBuf {
        self.at("/usr/bin/fleet-agent")
    }
    pub fn etc_dir(&self) -> PathBuf {
        self.at("/etc/fleet-agent")
    }
    pub fn config(&self) -> PathBuf {
        self.etc_dir().join("config.toml")
    }
    pub fn ca(&self) -> PathBuf {
        self.etc_dir().join("ca.pem")
    }
    pub fn state_dir(&self) -> PathBuf {
        self.at(crate::config::DEFAULT_STATE_DIR)
    }
    pub fn unit_dir(&self) -> PathBuf {
        self.at("/etc/systemd/system")
    }
    pub fn unit(&self) -> PathBuf {
        self.unit_dir().join(systemd::UNIT_NAME)
    }
    pub fn os_release(&self) -> [PathBuf; 2] {
        [self.at("/etc/os-release"), self.at("/usr/lib/os-release")]
    }

    /// The state directory a config uses, under `root`: the default one maps to [`Paths::state_dir`].
    pub fn state_dir_of(&self, config: &Config) -> PathBuf {
        if config.state_dir == Path::new(crate::config::DEFAULT_STATE_DIR) {
            self.state_dir()
        } else {
            config.state_dir.clone()
        }
    }
}

/// The installer's clock, so tests can run the approval countdown without waiting.
pub trait Clock {
    fn now(&self) -> Instant;
    /// Sleeps up to `duration`; returns `true` if interrupted (Ctrl-C or SIGTERM) instead.
    fn sleep(&self, duration: Duration) -> bool;
    fn interrupted(&self) -> bool;
}

/// The real clock; Ctrl-C and SIGTERM end a sleep at once.
pub struct SystemClock(pub Shutdown);

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, duration: Duration) -> bool {
        self.0.wait(duration)
    }
    fn interrupted(&self) -> bool {
        self.0.is_requested()
    }
}

/// Everything the installer needs from the machine it runs on.
pub struct Host {
    pub paths: Paths,
    /// Whether the process runs as root (preflight).
    pub is_root: bool,
    /// The uid every existing path must be owned by: the effective uid (root in production).
    pub owner_uid: u32,
    /// The `uname` machine, for example `x86_64`.
    pub machine: String,
    /// The running binary, which `install` copies into place.
    pub exe: PathBuf,
    pub system_ca_bundle: PathBuf,
    pub systemd: Box<dyn Systemd>,
    pub clock: Box<dyn Clock>,
    /// `FLEET_ENROLLMENT_TOKEN`, read once at startup.
    pub env_token: Option<String>,
    pub read_token: fn(TokenSource, Option<&str>) -> Result<token::Token, InstallError>,
    /// How long to wait for the service to become active, and how long it must then stay active.
    pub service_timeout: Duration,
    pub service_settle: Duration,
    /// The command as typed, with `sudo` in front, for the "run as root" hint.
    pub sudo_command: String,
}

impl Host {
    fn check_interrupt(&self) -> Result<(), InstallError> {
        if self.clock.interrupted() {
            return Err(interrupted());
        }
        Ok(())
    }
}

fn interrupted() -> InstallError {
    InstallError::new(
        Failure::Interrupted,
        "interrupted; the install stopped between steps, and nothing is half-written",
        "Run the same command again to finish the install, or `sudo fleet-agent uninstall` to remove what was installed.",
    )
}

/// `install` options from the command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstallOptions {
    pub server: Option<String>,
    pub ca_file: Option<PathBuf>,
    pub token: Option<TokenSource>,
    pub reenroll: bool,
}

/// `uninstall` options from the command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UninstallOptions {
    pub keep_state: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Install(InstallOptions, Mode),
    Uninstall(UninstallOptions, Mode),
    Help(&'static str),
}

pub const INSTALL_USAGE: &str = "\
Usage: sudo fleet-agent install --server URL [OPTIONS]

Installs the agent, enrolls this VM, and starts the service. By default it starts onboarding: it
prints a page and a code, and an operator approves the VM in the dashboard. Re-running it on an
enrolled VM keeps the credential and repairs or upgrades the installation.

Options:
  --server URL      The agent API address, for example https://agent.example.lan
                    (optional on a re-run: the configured server is kept)
  --ca-file PATH    Extra CA certificate(s) for a server with a private certificate authority
  --token           Enroll with a pre-registered one-time token instead; asks for it on the terminal
  --token-stdin     Read the one-time token from standard input
                    (or set FLEET_ENROLLMENT_TOKEN; the token is never accepted on the command line)
  --reenroll        Start onboarding again, for a lost or revoked credential
  --quiet           Print only errors and the approval page and code
  --json            Print one JSON object per line, for scripts
  -h, --help        Print this help

Exit status: 0 installed, 1 a step failed, 2 usage error, 3 preflight failed (nothing changed),
4 rejected, 5 expired or invalid token, 6 server error, 130 interrupted.";

pub const UNINSTALL_USAGE: &str = "\
Usage: sudo fleet-agent uninstall [OPTIONS]

Stops and disables the service and removes the unit, the binaries, the config, and the state
directory, then lists what it removed. The host record on the server is not changed; retire the
host in the dashboard.

Options:
  --keep-state      Keep the config (with the credential) and the state directory for a reinstall
  --quiet           Print only errors
  --json            Print one JSON object per line, for scripts
  -h, --help        Print this help

Exit status: 0 removed (or nothing to remove), 1 a removal failed, 2 usage error, 3 not root.";

fn usage(what: impl Into<String>, command: &str) -> InstallError {
    InstallError::new(
        Failure::Usage,
        what,
        format!("See `fleet-agent {command} --help`."),
    )
}

/// Parses the arguments after `install` or `uninstall` (`args[0]` is the subcommand).
/// `env_token` is whether `FLEET_ENROLLMENT_TOKEN` is set.
pub fn parse(args: &[String], env_token: bool) -> Result<Command, InstallError> {
    let (command, rest) = args.split_first().expect("a subcommand");
    let mut mode = None;
    let mut set_mode = |m: Mode| {
        if mode.replace(m).is_some_and(|old| old != m) {
            return Err(usage("--quiet and --json cannot be combined", command));
        }
        Ok(())
    };
    let mut install = InstallOptions::default();
    let mut uninstall = UninstallOptions::default();
    let mut rest = rest.iter().peekable();
    while let Some(arg) = rest.next() {
        let is_install = command == "install";
        match arg.as_str() {
            "-h" | "--help" => {
                return Ok(Command::Help(if is_install {
                    INSTALL_USAGE
                } else {
                    UNINSTALL_USAGE
                }));
            }
            "--quiet" => set_mode(Mode::Quiet)?,
            "--json" => set_mode(Mode::Json)?,
            "--keep-state" if !is_install => uninstall.keep_state = true,
            "--reenroll" if is_install => install.reenroll = true,
            "--server" | "--ca-file" if is_install => {
                let value = rest
                    .next()
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| usage(format!("{arg} needs a value"), command))?;
                set_value(&mut install, arg, value, command)?;
            }
            "--token" | "--token-stdin" if is_install => {
                // A token on the command line would show in the process list and the shell history,
                // so `--token` takes no value. The value is not repeated in the error.
                if arg == "--token" && rest.peek().is_some_and(|next| !next.starts_with('-')) {
                    return Err(token_on_command_line());
                }
                let source = if arg == "--token" {
                    TokenSource::Prompt
                } else {
                    TokenSource::Stdin
                };
                if install.token.replace(source).is_some() {
                    return Err(usage(
                        "give the token only one way: --token or --token-stdin",
                        command,
                    ));
                }
            }
            other if is_install && other.starts_with("--token=") => {
                return Err(token_on_command_line());
            }
            other
                if is_install
                    && (other.starts_with("--server=") || other.starts_with("--ca-file=")) =>
            {
                let (flag, value) = other.split_once('=').expect("contains =");
                if value.is_empty() {
                    return Err(usage(format!("{flag} needs a value"), command));
                }
                set_value(&mut install, flag, value, command)?;
            }
            other => {
                // Never echo an argument that may be a secret pasted in the wrong place.
                let shown = if other.starts_with('-') {
                    other
                } else {
                    "(a value)"
                };
                return Err(usage(
                    format!("unrecognised argument for {command}: {shown}"),
                    command,
                ));
            }
        }
    }
    let mode = mode.unwrap_or(Mode::Human);
    if command == "uninstall" {
        return Ok(Command::Uninstall(uninstall, mode));
    }
    if env_token {
        if install.token.is_some() {
            return Err(usage(
                "FLEET_ENROLLMENT_TOKEN is set and --token or --token-stdin was given; give the token only one way",
                command,
            ));
        }
        install.token = Some(TokenSource::Env);
    }
    if install.reenroll && install.token.is_some() {
        return Err(usage(
            "--reenroll starts onboarding; to re-enroll with a one-time token, use --token (or --token-stdin) without --reenroll",
            command,
        ));
    }
    Ok(Command::Install(install, mode))
}

fn set_value(
    options: &mut InstallOptions,
    flag: &str,
    value: &str,
    command: &str,
) -> Result<(), InstallError> {
    let duplicate = if flag == "--server" {
        options.server.replace(value.to_owned()).is_some()
    } else {
        options.ca_file.replace(PathBuf::from(value)).is_some()
    };
    if duplicate {
        return Err(usage(format!("{flag} given more than once"), command));
    }
    Ok(())
}

fn token_on_command_line() -> InstallError {
    InstallError::new(
        Failure::Usage,
        "--token does not take a value: a token on the command line shows in the process list and the shell history",
        "Run the command with --token alone and paste the token when asked, or pass it with --token-stdin or the FLEET_ENROLLMENT_TOKEN environment variable. If the token was typed into a shared shell history, issue a new one in the dashboard.",
    )
}

/// Entry point for `fleet-agent install ...` and `fleet-agent uninstall ...` (`args` starts with the
/// subcommand).
pub fn main(args: Vec<String>) -> ExitCode {
    let env_token = std::env::var("FLEET_ENROLLMENT_TOKEN").ok();
    let stdout_tty = std::io::stdout().is_terminal();
    let command = match parse(&args, env_token.is_some()) {
        Ok(command) => command,
        Err(error) => {
            Ui::new(
                Mode::Human,
                false,
                Box::new(std::io::stdout()),
                Box::new(std::io::stderr()),
            )
            .error(&error);
            return ExitCode::from(error.failure.code());
        }
    };
    let mode = match &command {
        Command::Help(text) => {
            println!("{text}");
            return ExitCode::SUCCESS;
        }
        Command::Install(_, mode) | Command::Uninstall(_, mode) => *mode,
    };
    let mut ui = Ui::new(
        mode,
        stdout_tty,
        Box::new(std::io::stdout()),
        Box::new(std::io::stderr()),
    );
    // Ctrl-C and SIGTERM end waits and stop the installer between steps, never in the middle of a write.
    let shutdown = Shutdown::on_signals().unwrap_or_default();
    let euid = crate::owner::effective_uid();
    let host = Host {
        paths: Paths {
            root: PathBuf::from("/"),
        },
        is_root: euid == 0,
        owner_uid: euid,
        machine: crate::collect::HostSystem.machine().unwrap_or_default(),
        exe: std::env::current_exe().unwrap_or_default(),
        system_ca_bundle: PathBuf::from(crate::client::SYSTEM_CA_BUNDLE),
        systemd: Box::new(Systemctl),
        clock: Box::new(SystemClock(shutdown)),
        env_token,
        read_token: token::read,
        service_timeout: Duration::from_secs(30),
        service_settle: Duration::from_secs(3),
        sudo_command: sudo_command(&args),
    };
    let result = match &command {
        Command::Install(options, _) => install(&host, options, &mut ui),
        Command::Uninstall(options, _) => uninstall::uninstall(&host, options, &mut ui),
        Command::Help(_) => unreachable!(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            ui.error(&error);
            ExitCode::from(error.failure.code())
        }
    }
}

use crate::collect::System as _;

/// `sudo fleet-agent ARGS`, quoted for copying. Arguments never hold a secret (see [`parse`]).
fn sudo_command(args: &[String]) -> String {
    let quoted: Vec<String> = args
        .iter()
        .map(|a| {
            if !a.is_empty()
                && a.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./:=@,+".contains(c))
            {
                a.clone()
            } else {
                format!("'{}'", a.replace('\'', r"'\''"))
            }
        })
        .collect();
    format!("sudo fleet-agent {}", quoted.join(" "))
}

/// Runs `install` on `host`, printing progress and the final summary to `ui`.
pub fn install(host: &Host, options: &InstallOptions, ui: &mut Ui) -> Result<(), InstallError> {
    let started = host.clock.now();
    ui.title(&format!("fleet-agent {AGENT_VERSION}: install"));

    ui.step(1, 4, "Checking this VM");
    let plan = preflight::check(host, options, ui)?;
    host.check_interrupt()?;
    // Asked for after the checks, so nobody pastes a token into an install that cannot proceed.
    let token = match plan.token_source {
        Some(source) => Some((host.read_token)(source, host.env_token.as_deref())?),
        None => None,
    };
    host.check_interrupt()?;

    ui.step(2, 4, &format!("Installing fleet-agent {AGENT_VERSION}"));
    let _lock = layout::lock(host)?;
    let installed = layout::install(host, ui)?;
    host.check_interrupt()?;

    ui.step(3, 4, "Enrolling this VM");
    let enrolled = enroll::enroll(host, &plan, token, ui)?;
    host.check_interrupt()?;

    ui.step(4, 4, "Starting the agent");
    enroll::confirm(host, &enrolled, started, ui)?;
    host.check_interrupt()?;
    let service = start_service(host, installed.changed || enrolled.config_written, ui)?;

    let host_name = match &enrolled.host_name {
        Some(name) => name.clone(),
        None => format!(
            "enrolled earlier (credential key id {})",
            enrolled.config.credential.key_id()
        ),
    };
    ui.summary(
        "Done. fleet-agent is installed, enrolled, and running.",
        "installed",
        &[
            ("Host", host_name),
            ("Version", AGENT_VERSION.to_owned()),
            ("Service", service),
            ("Logs", "journalctl -u fleet-agent".to_owned()),
            ("Config", host.paths.config().display().to_string()),
        ],
        serde_json::json!({"server_url": enrolled.config.server_url, "key_id": enrolled.config.credential.key_id()}),
    );
    Ok(())
}

/// Enables the unit and (re)starts it if anything changed or it is not running, then waits until it
/// is active and stays active for a moment. Returns the service status line for the summary.
fn start_service(host: &Host, changed: bool, ui: &mut Ui) -> Result<String, InstallError> {
    let systemd = &*host.systemd;
    let step_failed = |what: &str, e: String| {
        InstallError::new(
            Failure::Failed,
            format!("{what} failed: {e}"),
            "Check `systemctl status fleet-agent`, fix the cause, then run the same install command again.",
        )
    };
    if !systemd.is_enabled() {
        systemd
            .systemctl(&["enable", systemd::UNIT_NAME])
            .map_err(|e| step_failed("systemctl enable fleet-agent", e))?;
        ui.detail("Enabled fleet-agent.service to start at boot.");
    }
    if !changed && systemd.state() == "active" {
        ui.detail("fleet-agent.service is already running this version; left running.");
        return Ok("active (running), enabled at boot".into());
    }
    systemd
        .systemctl(&["restart", systemd::UNIT_NAME])
        .map_err(|e| step_failed("systemctl restart fleet-agent", e))?;
    let deadline = host.clock.now() + host.service_timeout;
    let mut settled = false;
    loop {
        let state = systemd.state();
        match state.as_str() {
            "active" if settled => break,
            "active" => {
                settled = true;
                if host.clock.sleep(host.service_settle) {
                    return Err(interrupted());
                }
                continue;
            }
            "activating" | "reloading" if host.clock.now() < deadline => {}
            _ => {
                let what = if state == "activating" {
                    format!(
                        "fleet-agent.service did not start within {} seconds",
                        host.service_timeout.as_secs()
                    )
                } else {
                    format!("fleet-agent.service did not stay running (state: {state})")
                };
                return Err(InstallError::new(
                    Failure::Failed,
                    what,
                    "See why with `journalctl -u fleet-agent -n 50`, fix the cause, then run the same install command again.",
                ));
            }
        }
        settled = false;
        if host.clock.sleep(Duration::from_millis(500)) {
            return Err(interrupted());
        }
    }
    ui.detail("Started fleet-agent.service; it is running.");
    Ok("active (running), enabled at boot".into())
}

/// The shared parts of a successful enrollment or a kept credential.
pub struct Enrolled {
    pub config: Config,
    /// The host's name as the operator approved it, when the server told us.
    pub host_name: Option<String>,
    pub config_written: bool,
    /// Whether the credential was issued by this run (as opposed to kept from an earlier install).
    pub fresh: bool,
}

/// Facts the server needs to recognise this VM.
pub struct Facts {
    pub hostname: Option<String>,
    pub machine_id: Option<String>,
    pub os: Option<crate::collect::OsRelease>,
}

impl Facts {
    pub fn collect(paths: &Paths) -> Self {
        let inventory = crate::collect::Collector::with(
            paths.root.clone(),
            Arc::new(crate::collect::HostSystem),
            crate::collect::READ_TIMEOUT,
        )
        .collect();
        Self {
            hostname: inventory.hostname,
            machine_id: inventory.machine_id,
            os: inventory.os,
        }
    }
}
