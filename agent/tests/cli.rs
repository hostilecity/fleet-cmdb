//! Runs the built binary the way an operator would.

use std::process::Command;

fn agent() -> Command {
    Command::new(env!("CARGO_BIN_EXE_fleet-agent"))
}

#[test]
fn version_prints_agent_and_schema_versions() {
    let output = agent().arg("--version").output().expect("run fleet-agent");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 output");
    assert_eq!(
        stdout.trim_end(),
        format!("fleet-agent {} (agent schema 1)", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn unknown_argument_exits_with_usage_error() {
    let output = agent().arg("--bogus").output().expect("run fleet-agent");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("utf-8 output");
    assert!(stderr.contains("unrecognised argument: --bogus"));
}
