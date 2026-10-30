//! End-to-end tests of `install` and `uninstall` against a fake root directory, a recording systemd,
//! a clock that does not wait, and a local TLS server that answers like the Fleet CMDB agent API.
//! They run without root: the installer's ownership checks use the test's own uid.

use std::cell::Cell;
use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::*;
use crate::test_support::{TempDir, TestPki, TlsServer};

use crate::collect::contract;

const CREDENTIAL: &str = "fa_EXAMPLEkey0000000000.EXAMPLEsecret00000000000000000000000000000";
const OTHER_CREDENTIAL: &str = "fa_EXAMPLEkey1111111111.EXAMPLEsecret11111111111111111111111111111";
const DEVICE_CODE: &str = "EXAMPLE-device-code-000000000000000000000000000";
const TOKEN: &str = "EXAMPLE-enrollment-token-not-a-real-one-0001";
/// Fragments of every secret; none may appear in anything the installer prints.
const SECRETS: [&str; 4] = [
    "EXAMPLEsecret",
    "EXAMPLE-device-code",
    "EXAMPLE-enrollment-token",
    "EXAMPLE-secret",
];

// --- Fakes ----------------------------------------------------------------------------------------

#[derive(Clone, Default)]
struct FakeSystemd {
    calls: Arc<Mutex<Vec<String>>>,
    enabled: Arc<Mutex<bool>>,
    active: Arc<Mutex<bool>>,
    /// Answers to `is-active` after a restart, used before falling back to the real state.
    script: Arc<Mutex<VecDeque<String>>>,
    unavailable: Option<String>,
}

impl FakeSystemd {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
    fn count(&self, command: &str) -> usize {
        self.calls()
            .iter()
            .filter(|c| c.starts_with(command))
            .count()
    }
}

impl Systemd for FakeSystemd {
    fn unavailable(&self) -> Option<String> {
        self.unavailable.clone()
    }
    fn systemctl(&self, args: &[&str]) -> Result<String, String> {
        let call = args.join(" ");
        self.calls.lock().unwrap().push(call.clone());
        match args {
            ["daemon-reload"] | ["reset-failed", _] => Ok(String::new()),
            ["enable", _] => {
                *self.enabled.lock().unwrap() = true;
                Ok(String::new())
            }
            ["is-enabled", _] if *self.enabled.lock().unwrap() => Ok("enabled".into()),
            ["is-enabled", _] => Err("disabled".into()),
            ["restart", _] => {
                *self.active.lock().unwrap() = true;
                Ok(String::new())
            }
            ["is-active", _] => {
                if let Some(state) = self.script.lock().unwrap().pop_front() {
                    return if state == "active" {
                        Ok(state)
                    } else {
                        Err(state)
                    };
                }
                if *self.active.lock().unwrap() {
                    Ok("active".into())
                } else {
                    Err("inactive".into())
                }
            }
            ["disable", "--now", _] => {
                *self.enabled.lock().unwrap() = false;
                *self.active.lock().unwrap() = false;
                Ok(String::new())
            }
            _ => Err(format!("unexpected systemctl call: {call}")),
        }
    }
}

/// A clock that advances only when slept on; can simulate Ctrl-C after a number of sleeps.
struct FakeClock {
    start: Instant,
    offset: Cell<Duration>,
    sleeps: Cell<usize>,
    interrupt_after: Option<usize>,
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        self.start + self.offset.get()
    }
    fn sleep(&self, duration: Duration) -> bool {
        self.sleeps.set(self.sleeps.get() + 1);
        self.offset.set(self.offset.get() + duration);
        self.interrupted()
    }
    fn interrupted(&self) -> bool {
        self.interrupt_after.is_some_and(|n| self.sleeps.get() >= n)
    }
}

// --- Fixture --------------------------------------------------------------------------------------

struct Fixture {
    dir: TempDir,
    pki: TestPki,
    systemd: FakeSystemd,
    is_root: bool,
    machine: String,
    interrupt_after: Option<usize>,
    env_token: Option<String>,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new();
        for d in [
            "root/usr/lib",
            "root/usr/bin",
            "root/etc/systemd/system",
            "root/var/lib",
            "root/proc/sys/kernel",
        ] {
            fs::create_dir_all(dir.path(d)).unwrap();
        }
        fs::write(
            dir.path("root/etc/os-release"),
            "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nID=debian\n",
        )
        .unwrap();
        fs::write(
            dir.path("root/etc/machine-id"),
            "0123456789abcdef0123456789abcdef\n",
        )
        .unwrap();
        fs::write(
            dir.path("root/proc/sys/kernel/hostname"),
            "vm-01.example.lan\n",
        )
        .unwrap();
        fs::write(dir.path("exe"), "fake fleet-agent binary v1").unwrap();
        let pki = TestPki::generate();
        fs::write(dir.path("system-ca.pem"), &pki.ca_pem).unwrap();
        Self {
            dir,
            pki,
            systemd: FakeSystemd::default(),
            is_root: true,
            machine: "x86_64".into(),
            interrupt_after: None,
            env_token: None,
        }
    }

    fn paths(&self) -> Paths {
        Paths {
            root: self.dir.path("root"),
        }
    }

    fn host(&self) -> Host {
        Host {
            paths: self.paths(),
            is_root: self.is_root,
            owner_uid: crate::owner::effective_uid(),
            machine: self.machine.clone(),
            exe: self.dir.path("exe"),
            system_ca_bundle: self.dir.path("system-ca.pem"),
            systemd: Box::new(self.systemd.clone()),
            clock: Box::new(FakeClock {
                start: Instant::now(),
                offset: Cell::new(Duration::ZERO),
                sleeps: Cell::new(0),
                interrupt_after: self.interrupt_after,
            }),
            env_token: self.env_token.clone(),
            read_token: token::read,
            service_timeout: Duration::from_secs(30),
            service_settle: Duration::from_secs(3),
            sudo_command: "sudo fleet-agent install --server https://localhost".into(),
        }
    }

    fn server(&self, replies: Vec<String>) -> TlsServer {
        TlsServer::start(&self.pki, replies)
    }

    /// Runs `install` the way `main` does and returns the outcome and what was printed.
    fn install(&self, options: &InstallOptions, mode: Mode) -> Outcome {
        let (out, err) = (ui::Captured::default(), ui::Captured::default());
        let mut ui = Ui::new(mode, false, Box::new(out.clone()), Box::new(err.clone()));
        let result = install(&self.host(), options, &mut ui);
        if let Err(error) = &result {
            ui.error(error);
        }
        Outcome::new(result, out.text(), err.text())
    }

    fn uninstall(&self, options: &UninstallOptions, mode: Mode) -> Outcome {
        let (out, err) = (ui::Captured::default(), ui::Captured::default());
        let mut ui = Ui::new(mode, false, Box::new(out.clone()), Box::new(err.clone()));
        let result = uninstall::uninstall(&self.host(), options, &mut ui);
        if let Err(error) = &result {
            ui.error(error);
        }
        Outcome::new(result, out.text(), err.text())
    }

    fn config_text(&self) -> Option<String> {
        fs::read_to_string(self.paths().config()).ok()
    }

    /// Writes an enrolled config for `server` as a previous install would have.
    fn enrolled(&self, server: &TlsServer, extra: &str) {
        fs::create_dir_all(self.paths().etc_dir()).unwrap();
        fs::set_permissions(self.paths().etc_dir(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = self.paths().config();
        fs::write(
            &path,
            format!(
                "server_url = \"{}\"\ncredential = \"{CREDENTIAL}\"\n{extra}",
                url(server)
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// Every file and link under the fake root, as relative paths.
    fn tree(&self) -> Vec<String> {
        fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let meta = fs::symlink_metadata(&path).unwrap();
                if meta.is_dir() {
                    walk(&path, root, out);
                } else {
                    out.push(path.strip_prefix(root).unwrap().display().to_string());
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.dir.path("root"), &self.dir.path("root"), &mut out);
        out.sort();
        out
    }
}

struct Outcome {
    result: Result<(), InstallError>,
    out: String,
    err: String,
}

impl Outcome {
    fn new(result: Result<(), InstallError>, out: String, err: String) -> Self {
        for secret in SECRETS {
            assert!(
                !out.contains(secret) && !err.contains(secret),
                "secret printed:\n{out}\n{err}"
            );
        }
        Self { result, out, err }
    }
    fn ok(&self) {
        assert!(
            self.result.is_ok(),
            "{:?}\n{}\n{}",
            self.result,
            self.out,
            self.err
        );
    }
    fn failure(&self) -> InstallError {
        self.result
            .clone()
            .expect_err(&format!("expected a failure:\n{}", self.out))
    }
    fn all(&self) -> String {
        format!("{}{}", self.out, self.err)
    }
}

fn url(server: &TlsServer) -> String {
    format!("https://localhost:{}", server.port)
}

fn options(server: &TlsServer) -> InstallOptions {
    InstallOptions {
        server: Some(url(server)),
        ..InstallOptions::default()
    }
}

fn reply(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nX-Request-Id: req-1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn error_reply(status: &str, code: &str) -> String {
    reply(
        status,
        &format!(
            r#"{{"error":{{"code":"{code}","message":"x","request_id":"00000000-0000-4000-8000-000000000001"}}}}"#
        ),
    )
}

fn probe() -> String {
    error_reply("404 Not Found", "not_found")
}

fn onboarding_started() -> String {
    reply(
        "201 Created",
        &format!(
            r#"{{"device_code":"{DEVICE_CODE}","user_code":"WDJB-MJHT","verification_uri":"https://fleet.example.lan/onboard","verification_uri_complete":"https://fleet.example.lan/onboard/WDJB-MJHT","expires_in":600,"interval":5,"server_time":"2026-01-01T12:00:00Z"}}"#
        ),
    )
}

fn pending() -> String {
    reply(
        "202 Accepted",
        r#"{"status":"pending","server_time":"2026-01-01T12:00:00Z"}"#,
    )
}

fn approved(credential: &str) -> String {
    reply(
        "201 Created",
        &format!(
            r#"{{"status":"approved","credential":"{credential}","host_name":"Media server","server_time":"2026-01-01T12:00:05Z"}}"#
        ),
    )
}

fn heartbeat_ok() -> String {
    reply(
        "200 OK",
        r#"{"server_time":"2026-01-01T12:00:06Z","directives":[]}"#,
    )
}

fn body_of(request: &str) -> Value {
    serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap()
}

fn path_of(request: &str) -> &str {
    request.split_whitespace().nth(1).unwrap()
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

fn assert_preflight(outcome: &Outcome, expected: &[&str]) {
    let error = outcome.failure();
    assert_eq!(error.failure, Failure::Preflight, "{error}");
    assert_eq!(error.failure.code(), 3);
    for text in expected {
        assert!(
            outcome.err.contains(text),
            "expected {text:?} in:\n{}",
            outcome.err
        );
    }
    assert!(outcome.err.contains("Next: "), "{}", outcome.err);
    assert!(outcome.err.contains("(exit code 3)"), "{}", outcome.err);
}

// --- The full onboarding install ------------------------------------------------------------------

#[test]
fn onboarding_install_end_to_end() {
    let fx = Fixture::new();
    let server = fx.server(vec![
        probe(),
        onboarding_started(),
        pending(),
        approved(CREDENTIAL),
        heartbeat_ok(),
    ]);
    let outcome = fx.install(&options(&server), Mode::Human);
    let first_url = url(&server);
    let requests = server.finish();
    outcome.ok();

    // What was asked of the server, in order, and that each body matches the API contract.
    let paths: Vec<&str> = requests.iter().map(|r| path_of(r)).collect();
    assert_eq!(
        paths,
        [
            "/api/v1",
            "/api/v1/onboarding",
            "/api/v1/onboarding/token",
            "/api/v1/onboarding/token",
            "/api/v1/heartbeat"
        ]
    );
    contract::assert_conforms("v1", "onboarding.request", &body_of(&requests[1]));
    contract::assert_conforms("v1", "onboarding-token.request", &body_of(&requests[2]));
    contract::assert_conforms("v1", "heartbeat.request", &body_of(&requests[4]));
    assert_eq!(body_of(&requests[1])["hostname"], "vm-01.example.lan");
    assert_eq!(
        body_of(&requests[1])["machine_id"],
        "0123456789abcdef0123456789abcdef"
    );
    assert_eq!(body_of(&requests[2])["device_code"], DEVICE_CODE);
    for request in &requests[..4] {
        assert!(
            !request.to_ascii_lowercase().contains("authorization:"),
            "{request}"
        );
    }
    assert!(requests[4].contains(&format!("Bearer {CREDENTIAL}")));

    // The layout.
    let p = fx.paths();
    let binary = p
        .versions_dir()
        .join(crate::AGENT_VERSION)
        .join("fleet-agent");
    assert_eq!(
        fs::read_to_string(&binary).unwrap(),
        "fake fleet-agent binary v1"
    );
    assert_eq!(mode_of(&binary), 0o755);
    assert_eq!(
        fs::read_link(p.current()).unwrap(),
        Path::new("versions").join(crate::AGENT_VERSION)
    );
    assert!(!p.previous().exists());
    assert_eq!(
        fs::read_to_string(p.bin_link()).unwrap(),
        "fake fleet-agent binary v1"
    );
    assert_eq!(fs::read_to_string(p.unit()).unwrap(), systemd::UNIT);
    assert_eq!(mode_of(&p.unit()), 0o644);

    // The config: root only, holding the credential, loadable by the agent.
    assert_eq!(mode_of(&p.config()), 0o600);
    assert_eq!(mode_of(&p.etc_dir()), 0o700);
    let config = Config::load_as(&p.config(), crate::owner::effective_uid()).unwrap();
    assert_eq!(config.credential.expose_secret(), CREDENTIAL);
    assert_eq!(config.server_url, first_url);

    // The service.
    assert_eq!(
        fx.systemd.calls()[..2],
        [
            "daemon-reload".to_owned(),
            "is-enabled fleet-agent.service".to_owned()
        ]
    );
    assert!(
        fx.systemd
            .calls()
            .contains(&"enable fleet-agent.service".to_owned())
    );
    assert!(
        fx.systemd
            .calls()
            .contains(&"restart fleet-agent.service".to_owned())
    );

    // What the person saw.
    let out = &outcome.out;
    for text in [
        "[1/4] Checking this VM",
        "Debian GNU/Linux 13 (trixie), x86_64",
        "[2/4] Installing fleet-agent",
        "[3/4] Enrolling this VM",
        "https://fleet.example.lan/onboard/WDJB-MJHT",
        "    WDJB-MJHT",
        "Approved as \"Media server\".",
        "[4/4] Starting the agent",
        "The server accepted a heartbeat",
        "Done. fleet-agent is installed, enrolled, and running.",
        "Host:    Media server",
        "Logs:    journalctl -u fleet-agent",
    ] {
        assert!(out.contains(text), "expected {text:?} in:\n{out}");
    }
    // Not a terminal: no QR code and no carriage-return countdown.
    assert!(!out.contains('█') && !out.contains('\r'), "{out}");
    assert!(outcome.err.is_empty(), "{}", outcome.err);
}

#[test]
fn json_and_quiet_output() {
    let fx = Fixture::new();
    let server = fx.server(vec![
        probe(),
        onboarding_started(),
        approved(CREDENTIAL),
        heartbeat_ok(),
    ]);
    let outcome = fx.install(&options(&server), Mode::Json);
    let first_url = url(&server);
    server.finish();
    outcome.ok();
    let events: Vec<Value> = outcome
        .out
        .lines()
        .map(|l| serde_json::from_str(l).expect("JSON line"))
        .collect();
    let approval = events
        .iter()
        .find(|e| e["event"] == "approval_required")
        .unwrap();
    assert_eq!(approval["user_code"], "WDJB-MJHT");
    assert_eq!(
        approval["verification_uri_complete"],
        "https://fleet.example.lan/onboard/WDJB-MJHT"
    );
    let last = events.last().unwrap();
    assert_eq!(last["event"], "installed");
    assert_eq!(last["host"], "Media server");
    assert_eq!(last["key_id"], "fa_EXAMPLEkey0000000000");

    // Quiet: a re-run prints nothing at all on success.
    let server2 = fx.server(vec![probe(), heartbeat_ok()]);
    let text = fx
        .config_text()
        .unwrap()
        .replace(&first_url, &url(&server2));
    fs::write(fx.paths().config(), text).unwrap();
    let outcome = fx.install(&InstallOptions::default(), Mode::Quiet);
    server2.finish();
    outcome.ok();
    assert_eq!(outcome.all(), "");

    // Quiet onboarding prints only the approval line.
    let fx = Fixture::new();
    let server = fx.server(vec![
        probe(),
        onboarding_started(),
        approved(CREDENTIAL),
        heartbeat_ok(),
    ]);
    let outcome = fx.install(&options(&server), Mode::Quiet);
    server.finish();
    outcome.ok();
    assert_eq!(
        outcome.out,
        "Approve this VM at https://fleet.example.lan/onboard/WDJB-MJHT (code WDJB-MJHT) within 10 minutes.\n"
    );
}

#[test]
fn json_errors_end_with_one_object_carrying_the_exit_code() {
    let mut fx = Fixture::new();
    fx.is_root = false;
    let outcome = fx.install(&InstallOptions::default(), Mode::Json);
    assert_eq!(outcome.err, "");
    let events: Vec<Value> = outcome
        .out
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(events[0]["event"], "step");
    let event = events.last().unwrap();
    assert_eq!(event["event"], "error");
    assert_eq!(event["error"], "preflight_failed");
    assert_eq!(event["exit_code"], 3);
    assert!(event["next_step"].as_str().unwrap().contains("sudo"));
}

// --- Re-runs, upgrades, re-enrollment ---------------------------------------------------------------

#[test]
fn a_rerun_keeps_the_credential_and_changes_nothing() {
    let fx = Fixture::new();
    let server = fx.server(vec![
        probe(),
        onboarding_started(),
        approved(CREDENTIAL),
        heartbeat_ok(),
    ]);
    fx.install(&options(&server), Mode::Human).ok();
    let first_url = url(&server);
    server.finish();
    let config_before = fx.config_text().unwrap();
    let inode = fs::metadata(fx.paths().config()).unwrap().ino();
    let restarts = fx.systemd.count("restart");

    // No --server: the configured one is used. Only the probe and the heartbeat reach the server.
    let server2 = TlsServer::start(&fx.pki, vec![probe(), heartbeat_ok()]);
    // The config names the first server's port; point it at the second server instead.
    fs::write(
        fx.paths().config(),
        config_before.replace(&first_url, &url(&server2)),
    )
    .unwrap();
    let config_before = fx.config_text().unwrap();
    let outcome = fx.install(&InstallOptions::default(), Mode::Human);
    let requests = server2.finish();
    outcome.ok();
    assert_eq!(
        requests.iter().map(|r| path_of(r)).collect::<Vec<_>>(),
        ["/api/v1", "/api/v1/heartbeat"]
    );
    assert_eq!(fx.config_text().unwrap(), config_before);
    assert_eq!(
        fs::metadata(fx.paths().config()).unwrap().ino(),
        inode,
        "config rewritten"
    );
    assert!(
        outcome
            .out
            .contains("keeping the existing credential (key id fa_EXAMPLEkey0000000000)"),
        "{}",
        outcome.out
    );
    assert!(outcome.out.contains("already in place"), "{}", outcome.out);
    assert!(
        outcome
            .out
            .contains("already running this version; left running"),
        "{}",
        outcome.out
    );
    assert!(
        outcome
            .out
            .contains("enrolled earlier (credential key id fa_EXAMPLEkey0000000000)"),
        "{}",
        outcome.out
    );
    assert_eq!(
        fx.systemd.count("restart"),
        restarts,
        "a healthy agent was restarted"
    );
}

#[test]
fn a_new_binary_upgrades_keeps_the_previous_version_and_prunes_older_ones() {
    let fx = Fixture::new();
    let p = fx.paths();
    // An earlier install of 0.0.1 replaced 0.0.0.
    for v in ["0.0.0", "0.0.1"] {
        fs::create_dir_all(p.versions_dir().join(v)).unwrap();
        fs::write(p.versions_dir().join(v).join("fleet-agent"), v).unwrap();
    }
    std::os::unix::fs::symlink("versions/0.0.1", p.current()).unwrap();
    std::os::unix::fs::symlink("versions/0.0.0", p.previous()).unwrap();
    let server = fx.server(vec![probe(), heartbeat_ok()]);
    fx.enrolled(&server, "");
    *fx.systemd.active.lock().unwrap() = true;
    *fx.systemd.enabled.lock().unwrap() = true;
    let outcome = fx.install(&InstallOptions::default(), Mode::Human);
    server.finish();
    outcome.ok();
    assert_eq!(
        fs::read_link(p.current()).unwrap(),
        Path::new("versions").join(crate::AGENT_VERSION)
    );
    assert_eq!(
        fs::read_link(p.previous()).unwrap(),
        Path::new("versions/0.0.1")
    );
    assert!(!p.versions_dir().join("0.0.0").exists());
    assert!(p.versions_dir().join("0.0.1/fleet-agent").exists());
    assert!(
        outcome
            .out
            .contains("Previous version 0.0.1 kept for rollback."),
        "{}",
        outcome.out
    );
    assert_eq!(
        fx.systemd.count("restart"),
        1,
        "the new version must be started"
    );
}

#[test]
fn reenroll_replaces_the_credential_and_keeps_other_settings() {
    let fx = Fixture::new();
    let server = fx.server(vec![
        probe(),
        onboarding_started(),
        approved(OTHER_CREDENTIAL),
        heartbeat_ok(),
    ]);
    fx.enrolled(
        &server,
        "log_level = \"debug\"\n[heartbeat]\ninterval_seconds = 120\n",
    );
    let outcome = fx.install(
        &InstallOptions {
            reenroll: true,
            ..InstallOptions::default()
        },
        Mode::Human,
    );
    server.finish();
    outcome.ok();
    let config = Config::load_as(&fx.paths().config(), crate::owner::effective_uid()).unwrap();
    assert_eq!(config.credential.expose_secret(), OTHER_CREDENTIAL);
    assert_eq!(config.log_level, crate::config::LogLevel::Debug);
    assert_eq!(config.heartbeat.start, Duration::from_secs(120));
}

#[test]
fn a_revoked_credential_on_a_rerun_says_to_reenroll() {
    let fx = Fixture::new();
    let server = fx.server(vec![
        probe(),
        error_reply("401 Unauthorized", "unauthorized"),
    ]);
    fx.enrolled(&server, "");
    let before = fx.config_text();
    let outcome = fx.install(&InstallOptions::default(), Mode::Human);
    server.finish();
    let error = outcome.failure();
    assert_eq!(error.failure, Failure::Rejected);
    assert_eq!(error.failure.code(), 4);
    assert!(
        outcome
            .err
            .contains("no longer accepts this VM's credential"),
        "{}",
        outcome.err
    );
    assert!(
        outcome.err.contains("fleet-agent install --reenroll"),
        "{}",
        outcome.err
    );
    assert!(
        outcome.err.contains("fleet-agent install --token"),
        "{}",
        outcome.err
    );
    assert_eq!(fx.config_text(), before);
    assert_eq!(fx.systemd.count("restart"), 0);
}

#[test]
fn a_host_being_reenrolled_says_what_to_run() {
    let fx = Fixture::new();
    let server = fx.server(vec![
        probe(),
        error_reply("403 Forbidden", "reenrollment_required"),
    ]);
    fx.enrolled(&server, "");
    let outcome = fx.install(&InstallOptions::default(), Mode::Human);
    server.finish();
    assert_eq!(outcome.failure().failure, Failure::Rejected);
    assert!(outcome.err.contains("being re-enrolled"), "{}", outcome.err);
    assert!(outcome.err.contains("--reenroll"), "{}", outcome.err);
}

// --- The token path -------------------------------------------------------------------------------

fn enrolled_by_token() -> String {
    reply(
        "201 Created",
        &format!(
            r#"{{"credential":"{CREDENTIAL}","host_name":"Build runner","server_time":"2026-01-01T12:00:00Z"}}"#
        ),
    )
}

#[test]
fn token_install_needs_no_person_and_never_prints_the_token() {
    let mut fx = Fixture::new();
    fx.env_token = Some(format!("{TOKEN}\n"));
    let server = fx.server(vec![probe(), enrolled_by_token(), heartbeat_ok()]);
    let opts = InstallOptions {
        token: Some(TokenSource::Env),
        ..options(&server)
    };
    let outcome = fx.install(&opts, Mode::Human);
    let requests = server.finish();
    outcome.ok();
    assert_eq!(path_of(&requests[1]), "/api/v1/enroll");
    let body = body_of(&requests[1]);
    contract::assert_conforms("v1", "enroll.request", &body);
    assert_eq!(body["token"], TOKEN);
    assert!(
        outcome.out.contains("Enrolled as \"Build runner\"."),
        "{}",
        outcome.out
    );
    assert!(
        outcome.out.contains("Host:    Build runner"),
        "{}",
        outcome.out
    );
    assert!(!outcome.out.contains("Approve"), "{}", outcome.out);
    let config = fx.config_text().unwrap();
    assert!(config.contains(CREDENTIAL));
    assert!(!config.contains(TOKEN), "the token must not be stored");
}

#[test]
fn a_used_or_expired_token_exits_5_and_leaves_the_existing_config() {
    let mut fx = Fixture::new();
    fx.env_token = Some(TOKEN.into());
    let opts = |server: &TlsServer| InstallOptions {
        token: Some(TokenSource::Env),
        ..options(server)
    };

    // A first install: nothing is written.
    let server = fx.server(vec![
        probe(),
        error_reply("410 Gone", "enrollment_token_invalid"),
    ]);
    let outcome = fx.install(&opts(&server), Mode::Human);
    server.finish();
    let error = outcome.failure();
    assert_eq!((error.failure, error.failure.code()), (Failure::Expired, 5));
    assert!(
        outcome.err.contains("invalid, expired, or already used"),
        "{}",
        outcome.err
    );
    assert!(
        outcome.err.contains("Issue a new one-time token"),
        "{}",
        outcome.err
    );
    assert_eq!(fx.config_text(), None);

    // An enrolled VM: its config is untouched.
    let server = fx.server(vec![
        probe(),
        error_reply("410 Gone", "enrollment_token_invalid"),
    ]);
    fx.enrolled(&server, "");
    let before = fx.config_text();
    let outcome = fx.install(&opts(&server), Mode::Human);
    server.finish();
    assert_eq!(outcome.failure().failure, Failure::Expired);
    assert!(
        outcome.err.contains("existing enrollment is unchanged"),
        "{}",
        outcome.err
    );
    assert_eq!(fx.config_text(), before);
}

#[test]
fn a_malformed_token_is_refused_before_anything_is_installed() {
    let mut fx = Fixture::new();
    fx.env_token = Some("not a token".into());
    let server = fx.server(vec![probe()]);
    let opts = InstallOptions {
        token: Some(TokenSource::Env),
        ..options(&server)
    };
    let outcome = fx.install(&opts, Mode::Human);
    server.finish();
    assert_eq!(outcome.failure().failure, Failure::Usage);
    assert!(!outcome.err.contains("not a token"), "{}", outcome.err);
    assert!(!fx.paths().lib_dir().exists());
}

// --- Onboarding failures --------------------------------------------------------------------------

/// After a failed enrollment: the binary may be installed, but no config, and the service untouched.
fn assert_nothing_enrolled(fx: &Fixture) {
    assert_eq!(fx.config_text(), None);
    assert_eq!(fx.systemd.count("enable") + fx.systemd.count("restart"), 0);
    let tree = fx.tree();
    assert!(
        tree.iter()
            .all(|f| !f.contains("config") && !f.contains(fsx::TEMP_MARKER)),
        "{tree:?}"
    );
}

#[test]
fn a_rejected_request_exits_4_and_writes_no_credential() {
    let fx = Fixture::new();
    let server = fx.server(vec![
        probe(),
        onboarding_started(),
        pending(),
        error_reply("403 Forbidden", "onboarding_rejected"),
    ]);
    let outcome = fx.install(&options(&server), Mode::Human);
    server.finish();
    let error = outcome.failure();
    assert_eq!(
        (error.failure, error.failure.code()),
        (Failure::Rejected, 4)
    );
    assert!(
        outcome
            .err
            .contains("an operator rejected this VM's onboarding request"),
        "{}",
        outcome.err
    );
    assert!(
        outcome.err.contains("run the same command again"),
        "{}",
        outcome.err
    );
    assert_nothing_enrolled(&fx);
}

#[test]
fn an_expired_request_exits_5_whether_the_server_or_the_clock_says_so() {
    let fx = Fixture::new();
    let server = fx.server(vec![
        probe(),
        onboarding_started(),
        error_reply("410 Gone", "onboarding_expired"),
    ]);
    let outcome = fx.install(&options(&server), Mode::Human);
    server.finish();
    let error = outcome.failure();
    assert_eq!((error.failure, error.failure.code()), (Failure::Expired, 5));
    assert!(
        outcome
            .err
            .contains("expired before an operator approved it"),
        "{}",
        outcome.err
    );
    assert!(outcome.err.contains("within 10 minutes"), "{}", outcome.err);
    assert_nothing_enrolled(&fx);

    // Pending until the request runs out locally: 600 s at a 5 s interval is 119 polls after the first.
    let fx = Fixture::new();
    let mut replies = vec![probe(), reply("201 Created", &onboarding_body(10, 5))];
    replies.extend(std::iter::repeat_with(pending).take(1));
    let server = fx.server(replies);
    let outcome = fx.install(&options(&server), Mode::Human);
    server.finish();
    assert_eq!(outcome.failure().failure, Failure::Expired);
    assert!(
        outcome.out.contains("Waiting for approval (1 min left)"),
        "{}",
        outcome.out
    );
    assert_nothing_enrolled(&fx);
}

fn onboarding_body(expires_in: u64, interval: u64) -> String {
    format!(
        r#"{{"device_code":"{DEVICE_CODE}","user_code":"WDJB-MJHT","verification_uri":"https://fleet.example.lan/onboard","verification_uri_complete":"https://fleet.example.lan/onboard/WDJB-MJHT","expires_in":{expires_in},"interval":{interval},"server_time":"2026-01-01T12:00:00Z"}}"#
    )
}

#[test]
fn ctrl_c_while_waiting_exits_130_and_writes_no_credential() {
    let mut fx = Fixture::new();
    fx.interrupt_after = Some(2);
    let server = fx.server(vec![probe(), onboarding_started()]);
    let outcome = fx.install(&options(&server), Mode::Human);
    server.finish();
    let error = outcome.failure();
    assert_eq!(
        (error.failure, error.failure.code()),
        (Failure::Interrupted, 130)
    );
    assert!(
        outcome.err.contains("cancelled while waiting for approval"),
        "{}",
        outcome.err
    );
    assert!(
        outcome.err.contains("Run the same command again"),
        "{}",
        outcome.err
    );
    assert_nothing_enrolled(&fx);
}

#[test]
fn network_errors_while_waiting_are_retried_and_429_slows_polling() {
    let fx = Fixture::new();
    let server = fx.server(vec![
        probe(),
        onboarding_started(),
        reply("503 Service Unavailable", "down"),
        reply(
            "429 Too Many Requests",
            r#"{"error":{"code":"rate_limited","message":"x","request_id":"r"}}"#,
        ),
        pending(),
        approved(CREDENTIAL),
        heartbeat_ok(),
    ]);
    let outcome = fx.install(&options(&server), Mode::Human);
    server.finish();
    outcome.ok();
    assert!(
        outcome
            .err
            .contains("cannot reach the server to check for approval (HTTP 503); still trying"),
        "{}",
        outcome.err
    );
    assert!(
        outcome.out.contains("Back in contact with the server"),
        "{}",
        outcome.out
    );
}

#[test]
fn a_server_error_when_starting_onboarding_exits_6() {
    let fx = Fixture::new();
    let server = fx.server(vec![
        probe(),
        error_reply("500 Internal Server Error", "internal_error"),
    ]);
    let outcome = fx.install(&options(&server), Mode::Human);
    server.finish();
    let error = outcome.failure();
    assert_eq!((error.failure, error.failure.code()), (Failure::Server, 6));
    assert!(
        outcome
            .err
            .contains("the server failed during onboarding (HTTP 500)"),
        "{}",
        outcome.err
    );
    assert!(outcome.err.contains("request id"), "{}", outcome.err);
    assert_nothing_enrolled(&fx);

    let fx = Fixture::new();
    let server = fx.server(vec![
        probe(),
        error_reply("426 Upgrade Required", "agent_version_unsupported"),
    ]);
    let outcome = fx.install(&options(&server), Mode::Human);
    server.finish();
    assert_eq!(outcome.failure().failure, Failure::Server);
    assert!(
        outcome.err.contains("Download the current agent"),
        "{}",
        outcome.err
    );

    let fx = Fixture::new();
    let server = fx.server(vec![
        probe(),
        error_reply("429 Too Many Requests", "rate_limited"),
    ]);
    let outcome = fx.install(&options(&server), Mode::Human);
    server.finish();
    assert_eq!(outcome.failure().failure, Failure::Server);
    assert!(
        outcome
            .err
            .contains("too many onboarding requests are already open"),
        "{}",
        outcome.err
    );
}

#[test]
fn a_hostile_onboarding_answer_is_refused_before_anything_is_shown() {
    let fx = Fixture::new();
    let body = onboarding_body(600, 5).replace("WDJB-MJHT\",\"expires", "\\u001b[2J\",\"expires");
    let server = fx.server(vec![probe(), reply("201 Created", &body)]);
    let outcome = fx.install(&options(&server), Mode::Human);
    server.finish();
    assert_eq!(outcome.failure().failure, Failure::Server);
    assert!(!outcome.all().contains('\u{1b}'));
}

#[test]
fn the_server_dropping_after_enrollment_keeps_the_credential_for_a_rerun() {
    let fx = Fixture::new();
    // Approved, then every heartbeat attempt fails: the TLS server has no more replies.
    let server = fx.server(vec![
        probe(),
        onboarding_started(),
        approved(CREDENTIAL),
        reply("502 Bad Gateway", ""),
        reply("502 Bad Gateway", ""),
        reply("502 Bad Gateway", ""),
        reply("502 Bad Gateway", ""),
    ]);
    let outcome = fx.install(&options(&server), Mode::Human);
    let first_url = url(&server);
    server.finish();
    let error = outcome.failure();
    assert_eq!(error.failure, Failure::Server);
    assert!(
        outcome.err.contains("The credential is saved"),
        "{}",
        outcome.err
    );
    assert!(fx.config_text().unwrap().contains(CREDENTIAL));
    assert_eq!(fx.systemd.count("restart"), 0);

    // The re-run keeps the credential and finishes.
    let server2 = fx.server(vec![probe(), heartbeat_ok()]);
    let text = fx
        .config_text()
        .unwrap()
        .replace(&first_url, &url(&server2));
    fs::write(fx.paths().config(), text).unwrap();
    let outcome = fx.install(&InstallOptions::default(), Mode::Human);
    server2.finish();
    outcome.ok();
    assert_eq!(fx.systemd.count("restart"), 1);
}

// --- Interrupted installs and unsafe paths ----------------------------------------------------------

#[test]
fn leftovers_of_an_interrupted_install_are_cleaned_up_by_a_rerun() {
    let fx = Fixture::new();
    let p = fx.paths();
    // A run killed mid-write: a temporary config (with a credential), a half-copied binary, a temp link.
    fs::create_dir_all(p.etc_dir()).unwrap();
    fs::set_permissions(p.etc_dir(), fs::Permissions::from_mode(0o700)).unwrap();
    let temp_config = p
        .etc_dir()
        .join(format!(".config.toml{}1-0", fsx::TEMP_MARKER));
    fs::write(&temp_config, format!("credential = \"{OTHER_CREDENTIAL}\"")).unwrap();
    let version_dir = p.versions_dir().join(crate::AGENT_VERSION);
    fs::create_dir_all(&version_dir).unwrap();
    let temp_binary = version_dir.join(format!(".fleet-agent{}1-0", fsx::TEMP_MARKER));
    fs::write(&temp_binary, "half").unwrap();
    let temp_link = p.lib_dir().join(format!(".current{}1-0", fsx::TEMP_MARKER));
    std::os::unix::fs::symlink("versions/x", &temp_link).unwrap();

    let server = fx.server(vec![
        probe(),
        onboarding_started(),
        approved(CREDENTIAL),
        heartbeat_ok(),
    ]);
    fx.install(&options(&server), Mode::Human).ok();
    server.finish();
    for path in [temp_config, temp_binary, temp_link] {
        assert!(
            fs::symlink_metadata(&path).is_err(),
            "{} left behind",
            path.display()
        );
    }
}

#[test]
fn a_second_installer_is_refused_while_one_runs() {
    let fx = Fixture::new();
    fs::create_dir_all(fx.paths().lib_dir()).unwrap();
    let _held = fsx::DirLock::try_lock(&fx.paths().lib_dir())
        .unwrap()
        .unwrap();
    let server = fx.server(vec![probe()]);
    let outcome = fx.install(&options(&server), Mode::Human);
    server.finish();
    assert_eq!(outcome.failure().failure, Failure::Failed);
    assert!(
        outcome
            .err
            .contains("another fleet-agent install or uninstall is running"),
        "{}",
        outcome.err
    );
}

#[test]
fn a_service_that_does_not_stay_up_fails_with_where_to_look() {
    let fx = Fixture::new();
    fx.systemd
        .script
        .lock()
        .unwrap()
        .extend(["activating", "active", "failed"].map(String::from));
    let server = fx.server(vec![
        probe(),
        onboarding_started(),
        approved(CREDENTIAL),
        heartbeat_ok(),
    ]);
    let outcome = fx.install(&options(&server), Mode::Human);
    server.finish();
    let error = outcome.failure();
    assert_eq!((error.failure, error.failure.code()), (Failure::Failed, 1));
    assert!(
        outcome.err.contains("did not stay running (state: failed)"),
        "{}",
        outcome.err
    );
    assert!(
        outcome.err.contains("journalctl -u fleet-agent"),
        "{}",
        outcome.err
    );
}

// --- Preflight: every failure, its message, and exit code 3 ------------------------------------------

/// Preflight failures change nothing on the VM.
fn assert_untouched(fx: &Fixture) {
    assert!(!fx.paths().lib_dir().exists());
    assert!(
        fx.systemd.calls().iter().all(|c| c.starts_with("is-")),
        "{:?}",
        fx.systemd.calls()
    );
}

#[test]
fn preflight_not_root() {
    let mut fx = Fixture::new();
    fx.is_root = false;
    let outcome = fx.install(&InstallOptions::default(), Mode::Human);
    assert_preflight(
        &outcome,
        &[
            "install must run as root",
            "Run it again with sudo: sudo fleet-agent install",
        ],
    );
    assert_untouched(&fx);
}

#[test]
fn preflight_not_debian_13() {
    let fx = Fixture::new();
    fs::write(
        fx.dir.path("root/etc/os-release"),
        "PRETTY_NAME=\"Ubuntu 24.04 LTS\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n",
    )
    .unwrap();
    let outcome = fx.install(&InstallOptions::default(), Mode::Human);
    assert_preflight(
        &outcome,
        &[
            "this VM runs Ubuntu 24.04 LTS, not Debian 13",
            "Debian 13 on x86_64 only (DEC-01)",
        ],
    );
    fs::write(
        fx.dir.path("root/etc/os-release"),
        "ID=debian\nVERSION_ID=\"12\"\n",
    )
    .unwrap();
    assert_preflight(
        &fx.install(&InstallOptions::default(), Mode::Human),
        &["not Debian 13"],
    );
    fs::remove_file(fx.dir.path("root/etc/os-release")).unwrap();
    assert_preflight(
        &fx.install(&InstallOptions::default(), Mode::Human),
        &["cannot read /etc/os-release"],
    );
    assert_untouched(&fx);
}

#[test]
fn preflight_not_x86_64() {
    let mut fx = Fixture::new();
    fx.machine = "aarch64".into();
    let outcome = fx.install(&InstallOptions::default(), Mode::Human);
    assert_preflight(&outcome, &["architecture is aarch64, not x86_64"]);
}

#[test]
fn preflight_no_systemd() {
    let mut fx = Fixture::new();
    fx.systemd.unavailable =
        Some("systemd is not running on this machine (no /run/systemd/system)".into());
    let outcome = fx.install(&InstallOptions::default(), Mode::Human);
    assert_preflight(&outcome, &["systemd is not running", "booted with systemd"]);
}

#[test]
fn preflight_server_unreachable() {
    let fx = Fixture::new();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let opts = InstallOptions {
        server: Some(format!("https://localhost:{port}")),
        ..InstallOptions::default()
    };
    let outcome = fx.install(&opts, Mode::Human);
    assert_preflight(
        &outcome,
        &[
            &format!("cannot reach https://localhost:{port}"),
            "Check the address",
        ],
    );
    assert_untouched(&fx);
}

#[test]
fn preflight_untrusted_certificate_and_ca_file() {
    let fx = Fixture::new();
    // The VM trusts a different CA from the one that signed the server's certificate.
    fs::write(fx.dir.path("system-ca.pem"), TestPki::generate().ca_pem).unwrap();
    let server = fx.server(vec![probe()]);
    let outcome = fx.install(&options(&server), Mode::Human);
    server.finish();
    assert_preflight(
        &outcome,
        &[
            "presented a certificate this VM does not trust",
            "--ca-file",
        ],
    );
    assert_untouched(&fx);

    // A --ca-file that is not a certificate.
    let bad = fx.dir.write("bad.pem", "not a certificate");
    let server = fx.server(vec![]);
    let outcome = fx.install(
        &InstallOptions {
            ca_file: Some(bad),
            ..options(&server)
        },
        Mode::Human,
    );
    server.finish();
    assert_preflight(
        &outcome,
        &["--ca-file cannot be used", "contains no PEM certificate"],
    );

    // The right --ca-file works and is copied next to the config.
    let ca = fx.dir.write("server-ca.pem", &fx.pki.ca_pem);
    let server = fx.server(vec![
        probe(),
        onboarding_started(),
        approved(CREDENTIAL),
        heartbeat_ok(),
    ]);
    let outcome = fx.install(
        &InstallOptions {
            ca_file: Some(ca),
            ..options(&server)
        },
        Mode::Human,
    );
    server.finish();
    outcome.ok();
    let config = Config::load_as(&fx.paths().config(), crate::owner::effective_uid()).unwrap();
    assert_eq!(config.ca_file.as_deref(), Some(fx.paths().ca().as_path()));
    assert_eq!(fs::read_to_string(fx.paths().ca()).unwrap(), fx.pki.ca_pem);
}

#[test]
fn preflight_not_the_agent_api() {
    let fx = Fixture::new();
    // The dashboard hostname answers /api/v1 with an empty 404 (HostSeparation).
    let server = fx.server(vec![reply("404 Not Found", "")]);
    let outcome = fx.install(&options(&server), Mode::Human);
    server.finish();
    assert_preflight(
        &outcome,
        &[
            "not as the Fleet CMDB agent API (HTTP 404)",
            "not the dashboard address",
        ],
    );
}

#[test]
fn preflight_server_errors_and_bad_urls() {
    let fx = Fixture::new();
    let server = fx.server(vec![reply("503 Service Unavailable", "")]);
    let outcome = fx.install(&options(&server), Mode::Human);
    server.finish();
    let error = outcome.failure();
    assert_eq!(error.failure, Failure::Server);
    assert!(
        outcome.err.contains("server error (503)"),
        "{}",
        outcome.err
    );

    for (server, expected) in [
        (None, "--server is required for a first install"),
        (Some("http://agent.example.lan"), "must use https"),
        (Some("https://agent.example.lan/api/v1"), "without a path"),
    ] {
        let outcome = fx.install(
            &InstallOptions {
                server: server.map(String::from),
                ..InstallOptions::default()
            },
            Mode::Human,
        );
        assert_eq!(outcome.failure().failure, Failure::Usage, "{server:?}");
        assert!(outcome.err.contains(expected), "{}", outcome.err);
    }
    assert_untouched(&fx);
}

#[test]
fn preflight_config_with_wrong_mode_or_owner_or_contents() {
    let fx = Fixture::new();
    let server = fx.server(vec![]);
    fx.enrolled(&server, "");
    let config = fx.paths().config();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).unwrap();
    let outcome = fx.install(&InstallOptions::default(), Mode::Human);
    assert_preflight(&outcome, &["not safe to use", "chmod 600"]);
    // Refused, never "fixed": the mode is left for the operator to correct.
    assert_eq!(mode_of(&config), 0o644);

    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let mut host_fx_uid = fx.host();
    host_fx_uid.owner_uid += 1;
    let (out, err) = (ui::Captured::default(), ui::Captured::default());
    let mut ui = Ui::new(Mode::Human, false, Box::new(out), Box::new(err.clone()));
    let error = install(&host_fx_uid, &InstallOptions::default(), &mut ui).unwrap_err();
    assert_eq!(error.failure, Failure::Preflight);
    assert!(error.what.contains("is owned by uid"), "{error}");

    fs::write(
        &config,
        "server_url = \"https://agent.example.lan\"\nbogus = 1\n",
    )
    .unwrap();
    let outcome = fx.install(&InstallOptions::default(), Mode::Human);
    assert_preflight(
        &outcome,
        &["is not valid", "unknown field `bogus`", "--reenroll"],
    );
    server.finish();
}

#[test]
fn preflight_symlinks_and_foreign_files_are_refused() {
    let elsewhere = TempDir::new();
    type Setup<'a> = Box<dyn Fn(&Paths) + 'a>;
    let cases: Vec<(&str, Setup)> = vec![
        (
            "/etc/fleet-agent is a symlink",
            Box::new(|p: &Paths| {
                std::os::unix::fs::symlink(elsewhere.root(), p.etc_dir()).unwrap()
            }),
        ),
        (
            "/usr/lib/fleet-agent is a symlink",
            Box::new(|p: &Paths| {
                std::os::unix::fs::symlink(elsewhere.root(), p.lib_dir()).unwrap()
            }),
        ),
        (
            "/var/lib/fleet-agent is a symlink",
            Box::new(|p: &Paths| {
                std::os::unix::fs::symlink(elsewhere.root(), p.state_dir()).unwrap()
            }),
        ),
        (
            "/var/lib/fleet-agent has mode 0755",
            Box::new(|p: &Paths| {
                fs::create_dir(p.state_dir()).unwrap();
                fs::set_permissions(p.state_dir(), fs::Permissions::from_mode(0o755)).unwrap();
            }),
        ),
        (
            "/usr/bin/fleet-agent exists and is not a symlink",
            Box::new(|p: &Paths| fs::write(p.bin_link(), "copied by hand").unwrap()),
        ),
        (
            "fleet-agent.service was not written by fleet-agent install",
            Box::new(|p: &Paths| fs::write(p.unit(), "[Service]\n").unwrap()),
        ),
        (
            "ca.pem is a symlink",
            Box::new(|p: &Paths| {
                fs::create_dir(p.etc_dir()).unwrap();
                std::os::unix::fs::symlink("/etc/ssl/certs/ca-certificates.crt", p.ca()).unwrap();
            }),
        ),
        (
            "/etc/fleet-agent has mode 0777, writable by group or others",
            Box::new(|p: &Paths| {
                fs::create_dir(p.etc_dir()).unwrap();
                fs::set_permissions(p.etc_dir(), fs::Permissions::from_mode(0o777)).unwrap();
            }),
        ),
    ];
    for (expected, setup) in cases {
        let fx = Fixture::new();
        setup(&fx.paths());
        let server = fx.server(vec![]);
        let outcome = fx.install(&options(&server), Mode::Human);
        server.finish();
        assert_preflight(&outcome, &[expected, "the installer will not use it"]);
        assert!(fx.systemd.calls().iter().all(|c| c.starts_with("is-")));
    }
}

#[test]
fn preflight_another_server_needs_reenroll() {
    let fx = Fixture::new();
    let server = fx.server(vec![]);
    fx.enrolled(&server, "");
    let outcome = fx.install(
        &InstallOptions {
            server: Some("https://agent2.example.lan".into()),
            ..InstallOptions::default()
        },
        Mode::Human,
    );
    server.finish();
    assert_preflight(
        &outcome,
        &["already enrolled with https://localhost", "add --reenroll"],
    );
}

// --- Uninstall --------------------------------------------------------------------------------------

#[test]
fn uninstall_removes_everything_install_created_and_nothing_else() {
    let fx = Fixture::new();
    let before = fx.tree();
    let server = fx.server(vec![
        probe(),
        onboarding_started(),
        approved(CREDENTIAL),
        heartbeat_ok(),
    ]);
    fx.install(&options(&server), Mode::Human).ok();
    server.finish();
    // What the agent itself creates at run time.
    fs::create_dir(fx.paths().state_dir()).unwrap();
    fs::set_permissions(fx.paths().state_dir(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(fx.paths().state_dir().join("boot_id"), "x").unwrap();
    // Something the operator added, which must survive.
    fs::write(
        fx.dir.path("root/etc/systemd/system/other.service"),
        "[Unit]\n",
    )
    .unwrap();

    let outcome = fx.uninstall(&UninstallOptions::default(), Mode::Human);
    outcome.ok();
    let mut expected = before.clone();
    expected.push("etc/systemd/system/other.service".into());
    expected.sort();
    assert_eq!(fx.tree(), expected);
    for dir in [
        fx.paths().lib_dir(),
        fx.paths().etc_dir(),
        fx.paths().state_dir(),
    ] {
        assert!(!dir.exists(), "{}", dir.display());
    }
    assert!(
        fx.systemd
            .calls()
            .contains(&"disable --now fleet-agent.service".to_owned())
    );
    assert!(
        outcome.out.contains("Done. fleet-agent is uninstalled."),
        "{}",
        outcome.out
    );
    assert!(
        outcome.out.contains("retire the host in the dashboard"),
        "{}",
        outcome.out
    );

    // Again: nothing to do, still success.
    let outcome = fx.uninstall(&UninstallOptions::default(), Mode::Human);
    outcome.ok();
    assert!(outcome.out.contains("Nothing to remove"), "{}", outcome.out);
}

#[test]
fn uninstall_keep_state_keeps_the_config_for_a_reinstall() {
    let fx = Fixture::new();
    let server = fx.server(vec![
        probe(),
        onboarding_started(),
        approved(CREDENTIAL),
        heartbeat_ok(),
    ]);
    fx.install(&options(&server), Mode::Human).ok();
    let first_url = url(&server);
    server.finish();
    let config = fx.config_text().unwrap();
    let outcome = fx.uninstall(&UninstallOptions { keep_state: true }, Mode::Json);
    outcome.ok();
    assert_eq!(fx.config_text().unwrap(), config);
    assert!(
        !fx.paths().lib_dir().exists()
            && !fx.paths().unit().exists()
            && !fx.paths().bin_link().exists()
    );
    let last: Value = serde_json::from_str(outcome.out.lines().last().unwrap()).unwrap();
    assert_eq!(last["event"], "uninstalled");
    assert!(last["kept"][0].as_str().unwrap().contains("--keep-state"));

    // Reinstalling keeps the credential: no onboarding.
    let server2 = fx.server(vec![probe(), heartbeat_ok()]);
    fs::write(
        fx.paths().config(),
        config.replace(&first_url, &url(&server2)),
    )
    .unwrap();
    fx.install(&InstallOptions::default(), Mode::Human).ok();
    assert_eq!(server2.finish().len(), 2);
}

#[test]
fn uninstall_leaves_what_it_did_not_create() {
    let fx = Fixture::new();
    let p = fx.paths();
    fs::create_dir(p.etc_dir()).unwrap();
    fs::write(p.etc_dir().join("notes.txt"), "mine").unwrap();
    fs::write(p.unit(), "[Service]\nExecStart=/bin/true\n").unwrap();
    fs::write(p.bin_link(), "someone else's binary").unwrap();
    let custom = fx.dir.path("custom-state");
    fs::create_dir(&custom).unwrap();
    fs::write(p.config(), format!("server_url = \"https://agent.example.lan\"\ncredential = \"{CREDENTIAL}\"\nstate_dir = \"{}\"\n", custom.display())).unwrap();
    fs::set_permissions(p.config(), fs::Permissions::from_mode(0o600)).unwrap();

    let outcome = fx.uninstall(&UninstallOptions::default(), Mode::Human);
    outcome.ok();
    assert!(p.etc_dir().join("notes.txt").exists());
    assert!(!p.config().exists());
    assert!(p.unit().exists() && p.bin_link().exists() && custom.exists());
    for text in [
        "not written by the installer",
        "not the installer's link",
        "notes.txt",
        "state_dir set in the config",
    ] {
        assert!(
            outcome.out.contains(text),
            "expected {text:?} in:\n{}",
            outcome.out
        );
    }
}

#[test]
fn uninstall_needs_root() {
    let mut fx = Fixture::new();
    fx.is_root = false;
    let outcome = fx.uninstall(&UninstallOptions::default(), Mode::Human);
    assert_eq!(outcome.failure().failure.code(), 3);
    assert!(
        outcome.err.contains("uninstall must run as root"),
        "{}",
        outcome.err
    );
}

// --- Command line ---------------------------------------------------------------------------------

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn install_options_parse() {
    let parsed = parse(
        &args(&[
            "install",
            "--server",
            "https://agent.example.lan",
            "--ca-file=/root/ca.pem",
            "--json",
        ]),
        false,
    )
    .unwrap();
    assert_eq!(
        parsed,
        Command::Install(
            InstallOptions {
                server: Some("https://agent.example.lan".into()),
                ca_file: Some(PathBuf::from("/root/ca.pem")),
                ..InstallOptions::default()
            },
            Mode::Json
        )
    );
    let Command::Install(o, Mode::Quiet) =
        parse(&args(&["install", "--token", "--quiet"]), false).unwrap()
    else {
        panic!()
    };
    assert_eq!(o.token, Some(TokenSource::Prompt));
    let Command::Install(o, _) = parse(&args(&["install", "--token-stdin"]), false).unwrap() else {
        panic!()
    };
    assert_eq!(o.token, Some(TokenSource::Stdin));
    let Command::Install(o, _) = parse(
        &args(&["install", "--server=https://agent.example.lan"]),
        true,
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(o.token, Some(TokenSource::Env));
    let Command::Install(o, _) = parse(&args(&["install", "--reenroll"]), false).unwrap() else {
        panic!()
    };
    assert!(o.reenroll);
    assert_eq!(
        parse(&args(&["uninstall", "--keep-state"]), false).unwrap(),
        Command::Uninstall(UninstallOptions { keep_state: true }, Mode::Human)
    );
    assert_eq!(
        parse(&args(&["install", "--help"]), false).unwrap(),
        Command::Help(INSTALL_USAGE)
    );
}

#[test]
fn a_token_on_the_command_line_is_refused_without_echoing_it() {
    for list in [
        vec!["install", "--token", TOKEN],
        vec!["install", &format!("--token={TOKEN}")],
        vec!["install", TOKEN],
    ] {
        let error = parse(&args(&list), false).unwrap_err();
        assert_eq!(error.failure, Failure::Usage);
        assert!(!error.to_string().contains("EXAMPLE"), "{error}");
        if list[1].starts_with("--token") {
            assert!(error.what.contains("process list"), "{error}");
        }
    }
    assert!(parse(&args(&["install", "--token"]), false).is_ok());
    assert!(
        parse(
            &args(&["install", "--token", "--server", "https://x.example.lan"]),
            false
        )
        .is_ok()
    );
}

#[test]
fn conflicting_and_unknown_options_are_usage_errors() {
    for list in [
        vec!["install", "--quiet", "--json"],
        vec!["install", "--token", "--token-stdin"],
        vec!["install", "--reenroll", "--token"],
        vec!["install", "--server"],
        vec!["install", "--server", "a", "--server", "b"],
        vec!["install", "--keep-state"],
        vec!["uninstall", "--reenroll"],
        vec!["uninstall", "--server", "x"],
        vec!["install", "--insecure"],
    ] {
        let error = parse(&args(&list), false).unwrap_err();
        assert_eq!(error.failure.code(), 2, "{list:?}");
    }
    let error = parse(&args(&["install", "--token"]), true).unwrap_err();
    assert!(error.what.contains("only one way"), "{error}");
}

#[test]
fn sudo_command_is_copyable() {
    assert_eq!(
        sudo_command(&args(&["install", "--server", "https://agent.example.lan"])),
        "sudo fleet-agent install --server https://agent.example.lan"
    );
    assert_eq!(
        sudo_command(&args(&["install", "--ca-file", "/root/my ca.pem"])),
        "sudo fleet-agent install --ca-file '/root/my ca.pem'"
    );
}

#[test]
fn every_failure_has_a_distinct_documented_exit_code() {
    let all = [
        Failure::Failed,
        Failure::Usage,
        Failure::Preflight,
        Failure::Rejected,
        Failure::Expired,
        Failure::Server,
        Failure::Interrupted,
    ];
    let codes: std::collections::HashSet<u8> = all.iter().map(|f| f.code()).collect();
    assert_eq!(codes.len(), all.len());
    for failure in all {
        assert!(
            INSTALL_USAGE.contains(&format!(
                "{} {}",
                failure.code(),
                match failure {
                    Failure::Failed => "a step failed",
                    Failure::Usage => "usage error",
                    Failure::Preflight => "preflight failed",
                    Failure::Rejected => "rejected",
                    Failure::Expired => "expired",
                    Failure::Server => "server error",
                    Failure::Interrupted => "interrupted",
                }
            )),
            "{failure:?}"
        );
    }
}

// --- Against a real server (manual) ---------------------------------------------------------------

/// Installs into a fake root against a running Fleet CMDB server, with the real clock. Run with
/// `FLEET_E2E_SERVER=https://localhost:3457 FLEET_E2E_CA=/path/ca.pem cargo test real_server -- --ignored --nocapture`,
/// and approve the request in the dashboard (or with `Onboarding::Approve` in `bin/rails runner`). With
/// `FLEET_E2E_TOKEN` set, enrolls with that one-time token instead.
#[test]
#[ignore = "needs a running server; see the doc comment"]
fn real_server_install_and_uninstall() {
    let server = std::env::var("FLEET_E2E_SERVER").expect("FLEET_E2E_SERVER");
    let ca = std::env::var("FLEET_E2E_CA").expect("FLEET_E2E_CA");
    let mut fx = Fixture::new();
    fx.env_token = std::env::var("FLEET_E2E_TOKEN").ok();
    fs::copy(&ca, fx.dir.path("system-ca.pem")).unwrap();
    let mut host = fx.host();
    host.clock = Box::new(SystemClock(Shutdown::default()));
    host.service_settle = Duration::from_millis(10);
    let options = InstallOptions {
        server: Some(server),
        token: fx.env_token.as_ref().map(|_| TokenSource::Env),
        ..InstallOptions::default()
    };
    let (out, err) = (ui::Captured::default(), ui::Captured::default());
    let mut ui = Ui::new(
        Mode::Human,
        false,
        Box::new(out.clone()),
        Box::new(err.clone()),
    );
    let result = install(&host, &options, &mut ui);
    println!("{}{}", out.text(), err.text());
    result.unwrap();
    // A re-run keeps the credential.
    let rerun = fx.install(&InstallOptions::default(), Mode::Human);
    println!("{}", rerun.out);
    rerun.ok();
    let outcome = fx.uninstall(&UninstallOptions::default(), Mode::Human);
    println!("{}", outcome.out);
    outcome.ok();
}
