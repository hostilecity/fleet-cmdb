//! Runs the built binary the way an operator would.

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SECRET: &str = "EXAMPLE-secret-not-a-real-credential-0001";
const CREDENTIAL: &str = "EXAMPLEkey01.EXAMPLE-secret-not-a-real-credential-0001";
const EXIT_CONFIG: i32 = 78;

fn agent() -> Command {
    Command::new(env!("CARGO_BIN_EXE_fleet-agent"))
}

/// A temporary directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let dir = std::env::temp_dir().join(format!(
            "fleet-agent-cli-{name}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// Writes a config file with the given mode.
    fn config(&self, text: &str, mode: u32) -> PathBuf {
        let path = self.0.join("config.toml");
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn state_dir(&self) -> PathBuf {
        self.0.join("state")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn valid_config(server_url: &str, state_dir: &Path) -> String {
    format!(
        "server_url = \"{server_url}\"\ncredential = \"{CREDENTIAL}\"\nstate_dir = \"{}\"\n",
        state_dir.display()
    )
}

fn run_with(args: &[&str]) -> (Output, String, String) {
    let output = agent().args(args).output().expect("run fleet-agent");
    let stdout = String::from_utf8(output.stdout.clone()).expect("utf-8 output");
    let stderr = String::from_utf8(output.stderr.clone()).expect("utf-8 output");
    assert!(
        !stdout.contains(SECRET) && !stderr.contains(SECRET),
        "credential leaked:\n{stdout}\n{stderr}"
    );
    (output, stdout, stderr)
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

#[test]
fn help_lists_the_commands() {
    let (output, stdout, _) = run_with(&["--help"]);
    assert!(output.status.success());
    assert!(
        stdout.contains("check-config") && stdout.contains("run") && stdout.contains("--config")
    );
}

#[test]
fn check_config_validates_without_contacting_the_server() {
    // The server URL points at a local listener; check-config must never connect to it.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let scratch = Scratch::new("check");
    let path = scratch.config(&valid_config(&url, &scratch.state_dir()), 0o600);

    let (output, stdout, _) = run_with(&["check-config", "--config", path.to_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
    assert!(stdout.contains("config OK"), "{stdout}");
    assert!(
        stdout.contains("credential = <redacted> (key id EXAMPLEkey01)"),
        "{stdout}"
    );
    assert!(stdout.contains("heartbeat  = 60 s"), "{stdout}");
    assert!(
        listener.accept().is_err(),
        "check-config contacted the server"
    );
    assert!(
        !scratch.state_dir().exists(),
        "check-config must not create state"
    );
}

#[test]
fn missing_config_is_an_actionable_error() {
    let scratch = Scratch::new("missing");
    let path = scratch.0.join("absent.toml");
    for command in ["check-config", "run"] {
        let (output, _, stderr) = run_with(&[command, "--config", path.to_str().unwrap()]);
        assert_eq!(output.status.code(), Some(EXIT_CONFIG), "{command}");
        assert!(stderr.contains("not found"), "{stderr}");
        assert!(stderr.contains("fleet-agent install"), "{stderr}");
    }
}

#[test]
fn invalid_configs_are_rejected_with_a_reason() {
    let scratch = Scratch::new("invalid");
    let state = scratch.state_dir();
    let cases = [
        (
            valid_config("http://fleet-agent.example.lan", &state),
            "must use https",
        ),
        (
            format!(
                "{}insecure = true\n",
                valid_config("https://fleet-agent.example.lan", &state)
            ),
            "unknown field `insecure`",
        ),
        (
            format!(
                "{}[heartbeat]\ninterval_seconds = 1\n",
                valid_config("https://fleet-agent.example.lan", &state)
            ),
            "between 10 and 3600",
        ),
        (
            format!(
                "server_url = \"https://fleet-agent.example.lan\"\ncredential = \"{CREDENTIAL}\n"
            ),
            "line 2",
        ),
        (
            format!(
                "{}ca_file = \"/nonexistent/ca.pem\"\n",
                valid_config("https://fleet-agent.example.lan", &state)
            ),
            "cannot read `ca_file`",
        ),
    ];
    for (text, expected) in cases {
        let path = scratch.config(&text, 0o600);
        for command in ["check-config", "run"] {
            let (output, _, stderr) = run_with(&[command, "--config", path.to_str().unwrap()]);
            assert_eq!(
                output.status.code(),
                Some(EXIT_CONFIG),
                "{command}: {stderr}"
            );
            assert!(
                stderr.contains(expected),
                "{command}: expected {expected:?} in {stderr}"
            );
        }
    }
    assert!(!state.exists());
}

#[test]
fn config_readable_by_others_is_refused() {
    let scratch = Scratch::new("perms");
    let path = scratch.config(
        &valid_config("https://fleet-agent.example.lan", &scratch.state_dir()),
        0o644,
    );
    let (output, _, stderr) = run_with(&["check-config", "--config", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(EXIT_CONFIG));
    assert!(stderr.contains("chmod 600"), "{stderr}");
}

#[test]
fn run_starts_creates_state_and_stops_cleanly_on_sigterm() {
    let scratch = Scratch::new("run");
    let path = scratch.config(
        &valid_config("https://fleet-agent.example.lan", &scratch.state_dir()),
        0o600,
    );
    let mut child = agent()
        .args(["run", "--config", path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start fleet-agent");

    // Collect stdout on a thread; wait for the start line.
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut all = String::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.unwrap();
            if line.contains("fleet-agent started") {
                let _ = tx.send(());
            }
            all.push_str(&line);
            all.push('\n');
        }
        all
    });
    rx.recv_timeout(Duration::from_secs(20))
        .expect("agent did not log its start");

    let state = fs::metadata(scratch.state_dir()).expect("state directory created");
    assert_eq!(state.permissions().mode() & 0o7777, 0o700);

    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let status = child.wait().unwrap();
    assert!(status.success(), "agent did not exit cleanly: {status:?}");

    let logs = reader.join().unwrap();
    assert!(logs.contains("key_id=\"EXAMPLEkey01\""), "{logs}");
    assert!(logs.contains("shutdown requested"), "{logs}");
    assert!(logs.contains("fleet-agent stopped"), "{logs}");
    assert!(!logs.contains(SECRET), "credential leaked: {logs}");
}

#[test]
fn install_and_uninstall_have_their_own_help() {
    let (output, stdout, _) = run_with(&["--help"]);
    assert!(output.status.success());
    assert!(
        stdout.contains("install") && stdout.contains("uninstall"),
        "{stdout}"
    );
    let (output, stdout, _) = run_with(&["install", "--help"]);
    assert!(output.status.success());
    for text in [
        "--server URL",
        "--token-stdin",
        "--reenroll",
        "--json",
        "3 preflight failed",
    ] {
        assert!(stdout.contains(text), "{text}: {stdout}");
    }
    let (output, stdout, _) = run_with(&["uninstall", "--help"]);
    assert!(output.status.success());
    assert!(stdout.contains("--keep-state"), "{stdout}");
}

#[test]
fn install_refuses_a_token_on_the_command_line_without_repeating_it() {
    const TOKEN: &str = "EXAMPLE-enrollment-token-not-a-real-one-0001";
    for args in [
        vec![
            "install",
            "--server",
            "https://agent.example.lan",
            "--token",
            TOKEN,
        ],
        vec!["install", &format!("--token={TOKEN}")],
    ] {
        let output = agent().args(&args).output().expect("run fleet-agent");
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(all.contains("process list"), "{all}");
        assert!(!all.contains(TOKEN), "token echoed: {all}");
    }
}

#[test]
fn install_usage_errors_exit_2_before_touching_anything() {
    for args in [
        vec!["install", "--quiet", "--json"],
        vec!["install", "--bogus"],
        vec!["uninstall", "--server", "https://agent.example.lan"],
    ] {
        let (output, _, stderr) = run_with(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains("Next: See `fleet-agent"), "{stderr}");
    }
}

#[test]
fn verify_release_has_help_and_usage_errors() {
    let (output, stdout, _) = run_with(&["verify-release", "--help"]);
    assert!(output.status.success());
    assert!(stdout.contains("--manifest PATH"), "{stdout}");
    let (output, _, stderr) = run_with(&["verify-release", "--manifest", "m.json"]);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("are all required"), "{stderr}");
    let (_, stdout, _) = run_with(&["--help"]);
    assert!(stdout.contains("verify-release"), "{stdout}");
}

#[test]
fn verify_release_refuses_a_release_signed_by_a_key_it_does_not_embed() {
    // A throwaway key, generated here: the binary under test embeds only the keys in
    // release-keys/, so this release must not verify.
    let scratch = Scratch::new("verify-release");
    let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let binary = b"not really a binary";
    let sha: String = ring::digest::digest(&ring::digest::SHA256, binary)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let manifest = format!(
        "{{\"format\":\"fleet-agent-release-manifest/1\",\"version\":\"9.9.9\",\"target\":\"x86_64-unknown-linux-musl\",\"sha256\":\"{sha}\",\"size\":{}}}\n",
        binary.len()
    );
    let signature = minisign::sign(
        Some(&pair.pk),
        &pair.sk,
        std::io::Cursor::new(manifest.as_bytes()),
        None,
        None,
    )
    .unwrap()
    .into_string();
    let path = |name: &str| scratch.0.join(name);
    fs::write(path("m.json"), &manifest).unwrap();
    fs::write(path("m.json.minisig"), signature).unwrap();
    fs::write(path("bin"), binary).unwrap();
    let (output, stdout, stderr) = run_with(&[
        "verify-release",
        "--manifest",
        path("m.json").to_str().unwrap(),
        "--signature",
        path("m.json.minisig").to_str().unwrap(),
        "--binary",
        path("bin").to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1), "{stdout}{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("release NOT verified"), "{stderr}");
}
