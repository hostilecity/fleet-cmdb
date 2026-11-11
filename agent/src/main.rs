//! `fleet-agent`: reports host facts to the Fleet CMDB server.
//!
//! Commands: `run` (the default), `check-config`, `--version`, and `--help` (P1-A01); `install` and
//! `uninstall` (P1-A10, in [`install`]); `verify-release` (P1-PACKAGING, in [`release`]); `self-test`,
//! `update-supervise`, and `update-rollback` (P1-AGENT-UPDATE, in [`update`]). `run` sends heartbeats
//! and inventory reports ([`report`], P1-AGENT-REPORT) and acts on the server's update directive.

// The agent is built for Linux only (DEC-01): it reads `/proc`, runs under systemd, and some system
// structs differ elsewhere (on macOS `statvfs` counts are 32-bit, a deliberate compile error in
// `collect::sys`). Say so first, instead of leaving only the errors that follow from it.
#[cfg(not(target_os = "linux"))]
compile_error!(
    "fleet-agent builds only for Linux (DEC-01). On macOS, build and test it in a Linux container: \
     see \"Build and check\" in agent/README.md."
);

mod cli;
mod client;
mod collect;
mod config;
mod facts;
mod fsx;
mod install;
mod logging;
mod owner;
mod packages;
mod release;
mod report;
mod retry;
mod shutdown;
mod state;
mod tasks;
#[cfg(test)]
mod test_support;
mod update;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use client::Client;
use config::{Config, DEFAULT_CONFIG_PATH, Interval};
use shutdown::Shutdown;

/// Agent version. A release build gets it from the release run (`FLEET_AGENT_VERSION`, set by the Agent release
/// workflow, ADR 0018); any other build reports `Cargo.toml`'s, which is only the development version.
pub const AGENT_VERSION: &str = match option_env!("FLEET_AGENT_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

/// Version of the report payloads this agent sends (`schema_version`, an integer; DEC-08).
/// Increment it, with a migration path on the server, whenever a payload changes incompatibly (NFR-5).
pub const AGENT_SCHEMA_VERSION: u32 = 1;

/// Exit status for an invalid or unreadable config (`EX_CONFIG` from sysexits.h), so the systemd
/// unit can stop restarting an agent that cannot start until an operator fixes its config.
const EXIT_CONFIG: u8 = 78;
/// Exit status for a usage error.
const EXIT_USAGE: u8 = 2;

const USAGE: &str = "\
Usage: fleet-agent [COMMAND] [OPTIONS]

Commands:
  run           Run the agent (the default)
  check-config  Validate the config file and trusted certificates without contacting the server
  install       Install, enroll, and start the agent (see `fleet-agent install --help`)
  uninstall     Stop and remove the agent (see `fleet-agent uninstall --help`)
  verify-release
                Check a downloaded release's signature and checksum (see `fleet-agent verify-release --help`)
  self-test     Check that this binary can start with this host's config (run on a downloaded release)
  update-supervise, update-rollback
                Internal: run by the agent and by systemd while updating (see `fleet-agent self-test --help`)

Options:
  -c, --config PATH  Config file [default: /etc/fleet-agent/config.toml]
  -V, --version      Print the agent version and agent schema version
  -h, --help         Print this help";

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Run { config: PathBuf },
    CheckConfig { config: PathBuf },
    Version,
    Help,
}

/// Parses the arguments after the program name. Split by `lexopt`; error messages never repeat an
/// argument that could be a secret ([`cli::shown`]).
fn parse_args<I>(args: I) -> Result<Command, String>
where
    I: IntoIterator,
    I::Item: Into<std::ffi::OsString>,
{
    use lexopt::prelude::*;
    let mut parser = lexopt::Parser::from_args(args);
    let mut subcommand: Option<&'static str> = None;
    let mut config: Option<PathBuf> = None;
    // `--version` and `--help` stand alone.
    let mut only: Option<(Command, &'static str)> = None;
    let mut others = false;
    while let Some(arg) = parser.next().map_err(cli::error_text)? {
        let alone = match arg {
            Short('V') | Long("version") => Some((Command::Version, "--version")),
            Short('h') | Long("help") => Some((Command::Help, "--help")),
            _ => None,
        };
        if let Some((command, flag)) = alone {
            if others || only.is_some() {
                return Err(format!("{flag} cannot be combined with other arguments"));
            }
            only = Some((command, flag));
            continue;
        }
        if let Some((_, flag)) = &only {
            return Err(format!("{flag} cannot be combined with other arguments"));
        }
        others = true;
        match arg {
            Short('c') | Long("config") => {
                let path = parser.value().map_err(cli::error_text)?;
                if path.is_empty() {
                    return Err("--config needs a path".into());
                }
                if config.replace(PathBuf::from(path)).is_some() {
                    return Err("--config given more than once".into());
                }
            }
            Value(value) => match value.to_str() {
                Some(name @ ("run" | "check-config")) if subcommand.is_none() => {
                    subcommand = Some(if name == "run" { "run" } else { "check-config" });
                }
                Some(name @ ("run" | "check-config")) => {
                    return Err(format!("unexpected argument: {name}"));
                }
                _ => {
                    return Err(format!(
                        "unrecognised argument: {}",
                        cli::shown(&value.to_string_lossy())
                    ));
                }
            },
            other => return Err(format!("unrecognised argument: {}", cli::arg(other))),
        }
    }
    if let Some((command, _)) = only {
        return Ok(command);
    }
    let config = config.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
    Ok(match subcommand {
        Some("check-config") => Command::CheckConfig { config },
        _ => Command::Run { config },
    })
}

/// The `--version` line, for example `fleet-agent 0.1.0 (agent schema 1)`.
fn version_line() -> String {
    format!("fleet-agent {AGENT_VERSION} (agent schema {AGENT_SCHEMA_VERSION})")
}

fn describe_interval(interval: &Interval) -> String {
    format!(
        "{} s (server may set {}..={} s)",
        interval.start.as_secs(),
        interval.min.as_secs(),
        interval.max.as_secs()
    )
}

/// `check-config`: validates the config and the trusted certificates. Never contacts the server.
fn check_config(path: &Path) -> ExitCode {
    let config = match Config::load(path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("fleet-agent: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    if let Err(e) = Client::new(&config) {
        eprintln!("fleet-agent: {e}");
        return ExitCode::from(EXIT_CONFIG);
    }
    println!("config OK: {}", path.display());
    println!("  server_url = {}", config.server_url);
    println!(
        "  credential = {} (key id {})",
        config.credential,
        config.credential.key_id()
    );
    println!("  log_level  = {}", config.log_level.as_str());
    match &config.ca_file {
        Some(ca) => println!("  ca_file    = {}", ca.display()),
        None => println!("  ca_file    = (none; system trust store only)"),
    }
    println!("  state_dir  = {}", config.state_dir.display());
    println!("  heartbeat  = {}", describe_interval(&config.heartbeat));
    println!("  inventory  = {}", describe_interval(&config.inventory));
    println!("  task_poll  = {}", describe_interval(&config.task_poll));
    // P3-A01: a bad [tasks] section does not stop `run` (every task is off), but it fails here.
    if let Some(problem) = config.tasks.problem() {
        println!("  tasks      = none enabled");
        eprintln!("fleet-agent: config file is not valid: {problem}");
        return ExitCode::from(EXIT_CONFIG);
    }
    println!("  tasks      = {}", describe_tasks(&config.tasks));
    for remark in config.tasks.remarks(tasks::IMPLEMENTED) {
        println!("  note: {remark}");
    }
    ExitCode::SUCCESS
}

/// The `tasks` line of `check-config`, for example
/// `refresh_reports (the default); restart may restart: nginx.service`.
fn describe_tasks(settings: &tasks::settings::TaskSettings) -> String {
    let mut out = match settings.enabled() {
        [] => "none enabled".to_owned(),
        enabled => enabled.join(", "),
    };
    if settings.uses_default_types() {
        out.push_str(" (the default)");
    }
    if !settings.allowed_services().is_empty() {
        out.push_str("; restart_service may restart: ");
        out.push_str(&settings.allowed_services().join(", "));
    }
    out
}

/// `run`: starts the agent and keeps it running until `SIGTERM` or `SIGINT`.
fn run(path: &Path) -> ExitCode {
    let started = Instant::now();
    let config = match Config::load(path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("fleet-agent: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    // Config problems, including an unusable `ca_file`, go to stderr before logging starts.
    let client = match Client::new(&config) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("fleet-agent: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    logging::init(config.log_level);

    match state::ensure_dir(&config.state_dir) {
        Ok(true) => tracing::info!(
            state_dir = %config.state_dir.display(),
            "created the state directory (mode 0700)"
        ),
        Ok(false) => {}
        Err(e) => {
            tracing::error!(
                state_dir = %config.state_dir.display(),
                "cannot prepare the state directory: {}",
                state::describe_write_error(&config.state_dir, &e)
            );
            return ExitCode::FAILURE;
        }
    }
    // Reporting works without state, so this does not stop the agent; but `fleet-agent install`
    // waits for the first heartbeat to be recorded there, so say plainly why it cannot be.
    if let Err(e) = state::check_writable(&config.state_dir) {
        tracing::error!(
            state_dir = %config.state_dir.display(),
            "cannot write the state directory: {}",
            state::describe_write_error(&config.state_dir, &e)
        );
    }
    let shutdown = match Shutdown::on_signals() {
        Ok(shutdown) => shutdown,
        Err(e) => {
            tracing::error!("cannot install signal handlers: {e}");
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(
        agent_version = AGENT_VERSION,
        schema_version = AGENT_SCHEMA_VERSION,
        server_url = config.server_url.as_str(),
        key_id = config.credential.key_id(),
        heartbeat_seconds = config.heartbeat.start.as_secs(),
        inventory_seconds = config.inventory.start.as_secs(),
        "fleet-agent started"
    );
    // P3-A01: the task settings fail safe, so say plainly when they turned every task off.
    match config.tasks.problem() {
        Some(problem) => tracing::error!("task configuration is not valid: {problem}"),
        None => {
            tracing::info!(
                tasks_enabled = describe_tasks(&config.tasks).as_str(),
                "task settings loaded"
            );
            for remark in config.tasks.remarks(tasks::IMPLEMENTED) {
                tracing::warn!("task settings: {remark}");
            }
        }
    }
    // Remote updates (P1-AGENT-UPDATE): the heartbeat loop hands the server's directive to this.
    let config_path = std::path::absolute(path).unwrap_or_else(|_| path.to_owned());
    let updater = update::Updater::from_config(&config, &config_path);
    // The startup check, then a timer: an update without a supervisor (killed, or a VM restart) gets one.
    updater.start_watchdog();
    // Heartbeats and inventory reports until SIGTERM or SIGINT (P1-AGENT-REPORT).
    if !report::run(&config, &client, &shutdown, started, &updater) {
        tracing::error!("fleet-agent stopped after an internal error");
        return ExitCode::FAILURE;
    }
    tracing::info!("fleet-agent stopped");
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    // `install` and `uninstall` have their own options and parser (P1-A10).
    // `args_os`, not `args`: a non-UTF-8 argument is a usage error, not a panic that prints it.
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if matches!(
        args.first().and_then(|a| a.to_str()),
        Some("install" | "uninstall")
    ) {
        return install::main(args);
    }
    if args.first().and_then(|a| a.to_str()) == Some("verify-release") {
        return release::main(args);
    }
    if matches!(
        args.first().and_then(|a| a.to_str()),
        Some("self-test" | "update-supervise" | "update-rollback")
    ) {
        return update::main(args);
    }
    match parse_args(args) {
        Ok(Command::Version) => {
            println!("{}", version_line());
            ExitCode::SUCCESS
        }
        Ok(Command::Help) => {
            println!("{}\n\n{USAGE}", version_line());
            ExitCode::SUCCESS
        }
        Ok(Command::CheckConfig { config }) => check_config(&config),
        Ok(Command::Run { config }) => run(&config),
        Err(message) => {
            eprintln!("fleet-agent: {message}\n\n{USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> PathBuf {
        PathBuf::from(DEFAULT_CONFIG_PATH)
    }

    #[test]
    fn version_help_and_run_parse() {
        let run = || Command::Run {
            config: default_config(),
        };
        for (args, expected) in [
            (vec!["--version"], Command::Version),
            (vec!["-V"], Command::Version),
            (vec!["--help"], Command::Help),
            (vec!["-h"], Command::Help),
            (vec![], run()),
            (vec!["run"], run()),
        ] {
            assert_eq!(parse_args(&args), Ok(expected), "{args:?}");
        }
    }

    #[test]
    fn config_option_parses_in_any_position() {
        let path = PathBuf::from("/tmp/agent.toml");
        for args in [
            vec!["check-config", "--config", "/tmp/agent.toml"],
            vec!["--config", "/tmp/agent.toml", "check-config"],
            vec!["check-config", "-c", "/tmp/agent.toml"],
            vec!["check-config", "--config=/tmp/agent.toml"],
        ] {
            assert_eq!(
                parse_args(&args),
                Ok(Command::CheckConfig {
                    config: path.clone()
                }),
                "{args:?}"
            );
        }
        assert_eq!(
            parse_args(["--config", "/tmp/agent.toml"]),
            Ok(Command::Run { config: path })
        );
    }

    #[test]
    fn unknown_and_extra_arguments_are_rejected() {
        for args in [
            &["--insecure"][..],
            &["--version", "extra"],
            &["run", "--version"],
            &["run", "check-config"],
            &["run", "run"],
            &["--config"],
            &["--config="],
            &["-c", "/a", "-c", "/b"],
            &["install"],
            &["verify-release"],
            &["self-test"],
            &["update-supervise"],
        ] {
            assert!(parse_args(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn version_line_names_both_versions() {
        assert_eq!(
            version_line(),
            format!("fleet-agent {AGENT_VERSION} (agent schema 1)")
        );
    }

    #[test]
    fn the_version_is_the_release_runs_or_else_cargo_tomls() {
        // The release workflow compiles its version in; every other build reports Cargo.toml's.
        let expected = option_env!("FLEET_AGENT_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"));
        assert_eq!(AGENT_VERSION, expected);
        assert!(!AGENT_VERSION.is_empty());
    }
}
