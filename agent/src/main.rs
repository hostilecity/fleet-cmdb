//! `fleet-agent`: reports host facts to the Fleet CMDB server.
//!
//! Commands: `run` (the default), `check-config`, `--version`, and `--help` (P1-A01); `install` and
//! `uninstall` (P1-A10, in [`install`]). `run` sends heartbeats and inventory reports ([`report`],
//! P1-AGENT-REPORT).

mod cli;
mod client;
mod collect;
mod config;
mod fsx;
mod install;
mod logging;
mod owner;
mod report;
mod retry;
mod shutdown;
mod state;
#[cfg(test)]
mod test_support;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use client::Client;
use config::{Config, DEFAULT_CONFIG_PATH, Interval};
use shutdown::Shutdown;

/// Agent release version, taken from `Cargo.toml`.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

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
            Long(name) => return Err(format!("unrecognised argument: {}", cli::long(name))),
            Short(c) => return Err(format!("unrecognised argument: {}", cli::short(c))),
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
    ExitCode::SUCCESS
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
                "cannot prepare the state directory: {e}"
            );
            return ExitCode::FAILURE;
        }
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
    // Heartbeats and inventory reports until SIGTERM or SIGINT (P1-AGENT-REPORT).
    if !report::run(&config, &client, &shutdown, started) {
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
    fn version_flags_parse() {
        assert_eq!(parse_args(["--version"]), Ok(Command::Version));
        assert_eq!(parse_args(["-V"]), Ok(Command::Version));
    }

    #[test]
    fn help_flags_parse() {
        assert_eq!(parse_args(["--help"]), Ok(Command::Help));
        assert_eq!(parse_args(["-h"]), Ok(Command::Help));
    }

    #[test]
    fn run_is_the_default() {
        let run = Command::Run {
            config: default_config(),
        };
        assert_eq!(parse_args(Vec::<String>::new()), Ok(run));
        assert_eq!(
            parse_args(["run"]),
            Ok(Command::Run {
                config: default_config()
            })
        );
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
        assert!(parse_args(["--insecure"]).is_err());
        assert!(parse_args(["--version", "extra"]).is_err());
        assert!(parse_args(["run", "--version"]).is_err());
        assert!(parse_args(["run", "check-config"]).is_err());
        assert!(parse_args(["run", "run"]).is_err());
        assert!(parse_args(["--config"]).is_err());
        assert!(parse_args(["--config="]).is_err());
        assert!(parse_args(["-c", "/a", "-c", "/b"]).is_err());
        assert!(parse_args(["install"]).is_err());
    }

    #[test]
    fn version_line_names_both_versions() {
        assert_eq!(
            version_line(),
            format!("fleet-agent {} (agent schema 1)", env!("CARGO_PKG_VERSION"))
        );
    }
}
