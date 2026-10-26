//! `fleet-agent`: reports host facts to the Fleet CMDB server.
//!
//! This is the Phase 0 skeleton (issue P0-AGENT). Only `--version` and `--help` are implemented;
//! enrollment, heartbeats, and inventory reporting arrive in the Phase 1 agent issues.

// The modules below are empty placeholders until the Phase 1 agent issues fill them.
#![allow(dead_code)]

mod client;
mod collect;
mod config;
mod logging;
mod report;
mod state;

use std::process::ExitCode;

/// Agent release version, taken from `Cargo.toml`.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of the report payloads this agent sends (`schema_version`, an integer; DEC-08).
/// Increment it, with a migration path on the server, whenever a payload changes incompatibly (NFR-5).
pub const AGENT_SCHEMA_VERSION: u32 = 1;

const USAGE: &str = "\
Usage: fleet-agent [OPTIONS]

Options:
  -V, --version  Print the agent version and agent schema version
  -h, --help     Print this help";

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Version,
    Help,
}

/// Parses the arguments after the program name. Commands are added by the Phase 1 agent issues.
fn parse_args<I, S>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Ok(Command::Help);
    };
    let command = match first.as_ref() {
        "-V" | "--version" => Command::Version,
        "-h" | "--help" => Command::Help,
        other => return Err(format!("unrecognised argument: {other}")),
    };
    match args.next() {
        Some(extra) => Err(format!("unexpected argument: {}", extra.as_ref())),
        None => Ok(command),
    }
}

/// The `--version` line, for example `fleet-agent 0.1.0 (agent schema 1)`.
fn version_line() -> String {
    format!("fleet-agent {AGENT_VERSION} (agent schema {AGENT_SCHEMA_VERSION})")
}

fn main() -> ExitCode {
    match parse_args(std::env::args().skip(1)) {
        Ok(Command::Version) => {
            println!("{}", version_line());
            ExitCode::SUCCESS
        }
        Ok(Command::Help) => {
            println!("{}\n\n{USAGE}", version_line());
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("fleet-agent: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_flags_parse() {
        assert_eq!(parse_args(["--version"]), Ok(Command::Version));
        assert_eq!(parse_args(["-V"]), Ok(Command::Version));
    }

    #[test]
    fn help_is_the_default() {
        assert_eq!(parse_args(Vec::<String>::new()), Ok(Command::Help));
        assert_eq!(parse_args(["--help"]), Ok(Command::Help));
    }

    #[test]
    fn unknown_and_extra_arguments_are_rejected() {
        assert!(parse_args(["--insecure"]).is_err());
        assert!(parse_args(["--version", "extra"]).is_err());
    }

    #[test]
    fn version_line_names_both_versions() {
        assert_eq!(
            version_line(),
            format!("fleet-agent {} (agent schema 1)", env!("CARGO_PKG_VERSION"))
        );
    }
}
