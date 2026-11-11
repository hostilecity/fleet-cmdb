//! The executor framework with test-only task types (P3-A03, P3-A05). No task type is registered in
//! this build, so these types stand in for the real ones: each is mapped to a catalog type id, so it
//! gets that entry's privilege, interruptibility, and timeout.
//!
//! Test code may run `/bin/sh` to build awkward process trees; the task module's non-test code may
//! not (`scripts/check-task-spawns.sh`).

use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};

use super::spawn::{ENVIRONMENT, Generated, ValidatedArg};
use super::unit::{Status, Units};
use super::*;
use crate::tasks::catalog::Privilege;

pub const A: &str = "0b5c8a4e-1d6f-4a3b-9c2d-7e8f9a0b1c2d";

/// A [`Control`] whose cancel and shutdown the test sets.
#[derive(Default)]
pub struct TestControl {
    pub shutdown: Shutdown,
    pub cancel: Cell<bool>,
    pub asked: Cell<u32>,
}

impl Control for TestControl {
    fn shutdown(&self) -> &Shutdown {
        &self.shutdown
    }

    fn cancel_requested(&self) -> bool {
        self.asked.set(self.asked.get() + 1);
        self.cancel.get()
    }
}

/// A test path or argument list that must be `'static`, as task programs are.
pub fn leak(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

pub fn leak_args(args: Vec<String>) -> &'static [&'static str] {
    Box::leak(
        args.into_iter()
            .map(leak)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceParams {
    service: String,
}

/// A test task type: runs its programs in order, under the catalog entry of `type_id`. With
/// `service`, it takes the catalog's `service` parameter and passes it as the operand of the last
/// program.
#[derive(Clone)]
pub struct Fixed {
    pub type_id: &'static str,
    pub programs: Vec<Program>,
    pub service: bool,
}

impl Fixed {
    pub fn new(type_id: &'static str, programs: Vec<Program>) -> Self {
        Self {
            type_id,
            programs,
            service: false,
        }
    }
}

struct FixedJob(Vec<Program>);

impl Job for FixedJob {
    fn run(&self, run: &mut Run<'_>) -> Result<Finish, Stop> {
        let mut last = None;
        for program in &self.0 {
            let exit = run.program(program)?;
            if !exit.success() {
                return Ok(Finish::from_exit(exit));
            }
            last = Some(exit);
        }
        Ok(Finish::from_exit(last.unwrap_or(Exit {
            code: Some(0),
            signal: None,
        })))
    }
}

impl TaskImpl for Fixed {
    fn type_id(&self) -> &'static str {
        self.type_id
    }

    fn prepare(&self, parameters: &Value, _: &TaskSettings) -> Result<Box<dyn Job>, &'static str> {
        let mut programs = self.programs.clone();
        if self.service {
            let params: ServiceParams = parse(parameters)?;
            let operand = ValidatedArg::service_unit(&params.service).ok_or("invalid_params")?;
            if let Some(last) = programs.last_mut() {
                last.operand = Some(operand);
            }
        } else {
            let _: NoParams = parse(parameters)?;
        }
        Ok(Box::new(FixedJob(programs)))
    }
}

pub fn program(path: &'static str, args: &'static [&'static str], privilege: Privilege) -> Program {
    Program {
        path,
        args,
        operand: None,
        privilege,
    }
}

/// A program running `script` with `/bin/sh` (tests only).
pub fn sh(script: String) -> Program {
    program(
        "/bin/sh",
        leak_args(vec!["-c".into(), script]),
        Privilege::ReadOnly,
    )
}

/// Scripted systemd for transient units.
#[derive(Default)]
pub struct FakeUnits {
    pub statuses: Mutex<VecDeque<Status>>,
    /// Returned once `statuses` is used up.
    pub last: Mutex<Status>,
    pub calls: Mutex<Vec<String>>,
    pub journal: Mutex<String>,
    pub fail_start: std::sync::atomic::AtomicBool,
}

impl FakeUnits {
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn call(&self, call: String) {
        self.calls.lock().unwrap().push(call);
    }
}

pub fn status(active: &str, sub: &str, code: Option<i32>, main: Option<i32>) -> Status {
    Status {
        load: "loaded".into(),
        active: active.into(),
        sub: sub.into(),
        result: if main == Some(0) {
            "success"
        } else {
            "exit-code"
        }
        .into(),
        main_code: code,
        main_status: main,
        invocation: "0123456789abcdef0123456789abcdef".into(),
    }
}

impl Units for FakeUnits {
    fn start(
        &self,
        name: &Generated,
        program: &Program,
        runtime_max_seconds: u64,
    ) -> Result<(), String> {
        self.call(format!(
            "start {} {} {runtime_max_seconds}",
            name.as_str(),
            program.path
        ));
        if self.fail_start.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("Failed to start transient service unit".into());
        }
        Ok(())
    }

    fn status(&self, name: &Generated) -> Result<Status, String> {
        self.call(format!("status {}", name.as_str()));
        let next = self.statuses.lock().unwrap().pop_front();
        Ok(next.unwrap_or_else(|| self.last.lock().unwrap().clone()))
    }

    fn stop(&self, name: &Generated) -> Result<(), String> {
        self.call(format!("stop {}", name.as_str()));
        Ok(())
    }

    fn journal(&self, invocation: &str, capture: &Arc<Mutex<Capture>>) -> Result<(), String> {
        self.call(format!("journal {invocation}"));
        spawn::lock(capture).push(self.journal.lock().unwrap().as_bytes());
        Ok(())
    }

    fn remove(&self, name: &Generated) {
        self.call(format!("remove {}", name.as_str()));
    }
}

/// Shares a [`FakeUnits`] with the registry, which owns its `Units`.
struct Shared(&'static FakeUnits);

impl Units for Shared {
    fn start(&self, name: &Generated, program: &Program, max: u64) -> Result<(), String> {
        self.0.start(name, program, max)
    }
    fn status(&self, name: &Generated) -> Result<Status, String> {
        self.0.status(name)
    }
    fn stop(&self, name: &Generated) -> Result<(), String> {
        self.0.stop(name)
    }
    fn journal(&self, invocation: &str, capture: &Arc<Mutex<Capture>>) -> Result<(), String> {
        self.0.journal(invocation, capture)
    }
    fn remove(&self, name: &Generated) {
        self.0.remove(name)
    }
}

pub fn fake_units() -> &'static FakeUnits {
    Box::leak(Box::default())
}

pub fn registry(tasks: Vec<Fixed>, units: &'static FakeUnits) -> Registry {
    Registry::new(
        tasks
            .into_iter()
            .map(|t| Box::new(t) as Box<dyn TaskImpl>)
            .collect(),
        TaskSettings::default(),
        Box::new(Shared(units)),
    )
}

pub fn delivered(task_type: &str, parameters: Value, timeout_seconds: u64) -> Delivered {
    Delivered {
        id: A.into(),
        task_type: task_type.into(),
        parameters,
        timeout_seconds,
        catalog_version: 1,
    }
}

/// Runs one task of a test type and returns what it produced.
fn run_one(task: Fixed, parameters: Value, timeout: u64, control: &TestControl) -> Execution {
    let type_id = task.type_id;
    let registry = registry(vec![task], fake_units());
    let delivered = delivered(type_id, parameters, timeout);
    registry
        .check(&delivered)
        .expect("the test task passes its checks");
    registry.run(&delivered, control).expect("not detached")
}

fn alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit(')')
            .next()
            .is_some_and(|rest| !rest.trim_start().starts_with('Z'))
    })
}

#[test]
fn the_environment_is_exactly_the_fixed_set_and_nothing_else_leaks_in() {
    // P3-A03 AC; C11: nothing of the agent's environment reaches a task.
    // SAFETY: a test-only variable no other test reads.
    unsafe { std::env::set_var("FLEET_TEST_SECRET", "must-not-leak") };
    let ran = run_one(
        Fixed::new(
            "refresh_reports",
            vec![program("/usr/bin/env", &[], Privilege::ReadOnly)],
        ),
        json!({}),
        60,
        &TestControl::default(),
    );
    assert_eq!(ran.outcome, Outcome::Succeeded, "{}", ran.output);
    let mut lines: Vec<&str> = ran.output.lines().collect();
    lines.sort_unstable();
    let mut expected: Vec<String> = ENVIRONMENT
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    expected.sort_unstable();
    assert_eq!(lines, expected);
}

#[test]
fn a_task_runs_in_slash_with_standard_input_closed_and_its_own_process_group() {
    let ran = run_one(
        Fixed::new(
            "refresh_reports",
            vec![sh("pwd; cat; echo stdin-closed; ps -o pgid= -p $$ | tr -d ' '; ps -o pgid= -p $PPID | tr -d ' '".into())],
        ),
        json!({}),
        60,
        &TestControl::default(),
    );
    let lines: Vec<&str> = ran.output.lines().collect();
    assert_eq!(&lines[..2], ["/", "stdin-closed"], "{}", ran.output);
    // The task's group is its own, not the agent's.
    assert_ne!(lines[2], lines[3], "{}", ran.output);
}

#[test]
fn exit_status_and_output_are_reported() {
    let ran = run_one(
        Fixed::new(
            "refresh_reports",
            vec![sh("echo out; echo err >&2; exit 3".into())],
        ),
        json!({}),
        60,
        &TestControl::default(),
    );
    assert_eq!(ran.outcome, Outcome::Failed);
    assert_eq!(ran.reason, Some("nonzero_exit"));
    assert_eq!(ran.exit_status, Some(3));
    assert!(ran.output.contains("out\n") && ran.output.contains("err\n"));
    assert!(!ran.output_truncated);
}

#[test]
fn gigabytes_of_output_are_bounded_and_marked_truncated() {
    // P3-A03 AC, threat model O6: 2 GiB through the pipe, at most the head and tail kept.
    let started = Instant::now();
    let ran = run_one(
        Fixed::new(
            "refresh_reports",
            vec![program(
                "/usr/bin/head",
                &["-c", "2147483648", "/dev/zero"],
                Privilege::ReadOnly,
            )],
        ),
        json!({}),
        600,
        &TestControl::default(),
    );
    assert_eq!(ran.outcome, Outcome::Succeeded);
    assert!(ran.output_truncated);
    assert!(ran.output.chars().count() <= output::MAX_OUTPUT_CHARS);
    assert!(ran.output.contains(&format!(
        "[fleet-agent: {} bytes of output were cut here]",
        2_147_483_648u64 - (output::HEAD_BYTES + output::TAIL_BYTES) as u64
    )));
    eprintln!("2 GiB of output read in {:?}", started.elapsed());
}

#[test]
fn a_task_past_its_deadline_is_killed_with_its_children_and_reported_timed_out() {
    // P3-A03 AC, AC-3.5 (agent half): the deadline ends the whole process group.
    let tmp = crate::test_support::TempDir::new();
    let pids = tmp.path("pids");
    let script = format!(
        "sleep 300 & echo $! > {p}; (sleep 300 & echo $! >> {p}; wait) & echo $! >> {p}; wait",
        p = pids.display()
    );
    let started = Instant::now();
    let ran = run_one(
        Fixed::new("refresh_reports", vec![sh(script)]),
        json!({}),
        1,
        &TestControl::default(),
    );
    assert_eq!(ran.outcome, Outcome::TimedOut, "{}", ran.output);
    assert_eq!(ran.reason, None);
    assert!(ran.output.contains("ran past its deadline of 1 seconds"));
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "{:?}",
        started.elapsed()
    );
    let pids: Vec<i32> = std::fs::read_to_string(&pids)
        .unwrap()
        .lines()
        .map(|l| l.trim().parse().unwrap())
        .collect();
    assert_eq!(pids.len(), 3);
    let until = Instant::now() + Duration::from_secs(5);
    while pids.iter().any(|p| alive(*p)) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(50));
    }
    for pid in pids {
        assert!(!alive(pid), "child {pid} outlived the task");
    }
}

#[test]
fn a_task_that_ignores_sigterm_is_killed_after_the_grace_period() {
    let started = Instant::now();
    let ran = run_one(
        Fixed::new(
            "refresh_reports",
            vec![sh("trap '' TERM; while :; do sleep 1; done".into())],
        ),
        json!({}),
        1,
        &TestControl::default(),
    );
    assert_eq!(ran.outcome, Outcome::TimedOut);
    let took = started.elapsed();
    assert!(took >= spawn::TERM_GRACE, "{took:?}");
    assert!(
        took < spawn::TERM_GRACE + Duration::from_secs(5),
        "{took:?}"
    );
}

#[test]
fn the_timeout_is_the_lower_of_the_servers_and_the_catalogs() {
    // C6: a server deadline far in the future does not lift the catalog's. Observed through a
    // transient unit's RuntimeMaxSec, which is the deadline plus the stop grace.
    let units = fake_units();
    let registry = registry(
        vec![Fixed::new(
            "apply_package_updates",
            vec![program(
                "/usr/bin/apt-get",
                &["update"],
                Privilege::PackageManager,
            )],
        )],
        units,
    );
    *units.last.lock().unwrap() = status("active", "exited", Some(1), Some(0));
    let catalog = Catalog::embedded()
        .unwrap()
        .get("apply_package_updates")
        .unwrap()
        .timeout_seconds;
    for (server, expected) in [(86_400, catalog), (10, 10)] {
        units.calls.lock().unwrap().clear();
        let ran = registry
            .run(
                &delivered("apply_package_updates", json!({}), server),
                &TestControl::default(),
            )
            .unwrap();
        assert_eq!(ran.outcome, Outcome::Succeeded);
        let start = units.calls()[0].clone();
        let max: u64 = start.rsplit(' ').next().unwrap().parse().unwrap();
        let want = expected + unit::STOP_GRACE.as_secs();
        assert!((want - 1..=want + 1).contains(&max), "{start}");
    }
}

#[test]
fn an_interruptible_task_is_stopped_when_the_server_cancels_it() {
    // P3-S05: refresh_reports is interruptible.
    let control = TestControl::default();
    control.cancel.set(true);
    let started = Instant::now();
    let ran = run_one(
        Fixed::new(
            "refresh_reports",
            vec![program("/bin/sleep", &["300"], Privilege::ReadOnly)],
        ),
        json!({}),
        600,
        &control,
    );
    assert_eq!(ran.outcome, Outcome::Cancelled);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_task_that_cannot_be_interrupted_ignores_a_cancel() {
    // DEC-14: restart_service runs to completion; the cancel is never honoured.
    let control = TestControl::default();
    control.cancel.set(true);
    let ran = run_one(
        Fixed::new(
            "restart_service",
            vec![program("/bin/sleep", &["0.3"], Privilege::ReadOnly)],
        ),
        json!({}),
        60,
        &control,
    );
    assert_eq!(ran.outcome, Outcome::Succeeded);
    assert!(control.asked.get() > 0, "progress was still sent");
}

#[test]
fn shutdown_stops_an_interruptible_task_and_reports_it_interrupted() {
    let control = TestControl::default();
    control.shutdown.request();
    let ran = run_one(
        Fixed::new(
            "refresh_reports",
            vec![program("/bin/sleep", &["300"], Privilege::ReadOnly)],
        ),
        json!({}),
        600,
        &control,
    );
    assert_eq!(ran.outcome, Outcome::Failed);
    assert_eq!(ran.reason, Some("interrupted"));
}

#[test]
fn shutdown_lets_a_short_task_that_cannot_be_interrupted_finish() {
    let control = TestControl::default();
    control.shutdown.request();
    let ran = run_one(
        Fixed::new(
            "restart_service",
            vec![program("/bin/sleep", &["0.5"], Privilege::ReadOnly)],
        ),
        json!({}),
        60,
        &control,
    );
    assert_eq!(ran.outcome, Outcome::Succeeded);
}

#[test]
fn a_program_that_cannot_start_is_an_agent_error() {
    let ran = run_one(
        Fixed::new(
            "refresh_reports",
            vec![program(
                "/nonexistent/fleet-agent-test",
                &[],
                Privilege::ReadOnly,
            )],
        ),
        json!({}),
        60,
        &TestControl::default(),
    );
    assert_eq!(ran.outcome, Outcome::Failed);
    assert_eq!(ran.reason, Some("agent_error"));
    assert!(
        ran.output
            .contains("could not start /nonexistent/fleet-agent-test")
    );
}

#[test]
fn a_program_needing_more_than_the_catalog_privilege_never_runs() {
    // P3-A05: a read_only type cannot run a package manager program, or reach systemd-run.
    let units = fake_units();
    let registry = registry(
        vec![Fixed::new(
            "refresh_reports",
            vec![program(
                "/usr/bin/apt-get",
                &["upgrade"],
                Privilege::PackageManager,
            )],
        )],
        units,
    );
    let ran = registry
        .run(
            &delivered("refresh_reports", json!({}), 60),
            &TestControl::default(),
        )
        .unwrap();
    assert_eq!(ran.outcome, Outcome::Failed);
    assert_eq!(ran.reason, Some("agent_error"));
    assert!(units.calls().is_empty());
}

#[test]
fn parameters_are_checked_strictly_and_refused_with_nothing_run() {
    // AC-3.1 (agent half), threat model C2.
    let units = fake_units();
    let restart = Fixed {
        type_id: "restart_service",
        programs: vec![program(
            "/usr/bin/systemctl",
            &["restart"],
            Privilege::ServiceManager,
        )],
        service: true,
    };
    let registry = registry(vec![Fixed::new("refresh_reports", vec![]), restart], units);
    for (task_type, parameters) in [
        ("refresh_reports", json!({"extra": 1})),
        ("refresh_reports", json!([])),
        ("refresh_reports", json!(null)),
        ("restart_service", json!({})),
        (
            "restart_service",
            json!({"service": "nginx.service", "now": true}),
        ),
        ("restart_service", json!({"service": 7})),
        ("restart_service", json!({"service": "--now.service"})),
        (
            "restart_service",
            json!({"service": "nginx.service; rm -rf /"}),
        ),
        ("restart_service", json!({"service": "$(reboot).service"})),
        ("restart_service", json!({"service": "../../x.service"})),
        ("restart_service", json!({"service": "nginx"})),
    ] {
        assert_eq!(
            registry
                .check(&delivered(task_type, parameters.clone(), 60))
                .err(),
            Some("invalid_params"),
            "{task_type} {parameters}"
        );
    }
    assert!(
        registry
            .check(&delivered(
                "restart_service",
                json!({"service": "nginx.service"}),
                60
            ))
            .is_ok()
    );
    assert_eq!(
        registry
            .check(&delivered("apply_package_updates", json!({}), 60))
            .err(),
        Some("not_supported")
    );
    assert!(!registry.implements("apply_package_updates"));
    assert!(!registry.implements("reboot"));
    assert!(registry.implements("restart_service"));
    assert!(units.calls().is_empty());
}

#[test]
fn a_package_manager_program_runs_in_a_transient_unit_and_its_journal_is_the_output() {
    let units = fake_units();
    units.statuses.lock().unwrap().extend([
        status("activating", "start", None, None),
        status("active", "running", None, None),
    ]);
    *units.last.lock().unwrap() = status("active", "exited", Some(1), Some(0));
    *units.journal.lock().unwrap() = "Reading package lists...\n".into();
    let registry = registry(
        vec![Fixed::new(
            "apply_package_updates",
            vec![program(
                "/usr/bin/apt-get",
                &["update"],
                Privilege::PackageManager,
            )],
        )],
        units,
    );
    let ran = registry
        .run(
            &delivered("apply_package_updates", json!({}), 3600),
            &TestControl::default(),
        )
        .unwrap();
    assert_eq!(ran.outcome, Outcome::Succeeded);
    assert_eq!(ran.exit_status, Some(0));
    assert_eq!(ran.output, "Reading package lists...\n");
    let unit = format!("fleet-agent-task-{A}-1.service");
    let calls = units.calls();
    assert!(calls[0].starts_with(&format!("start {unit} /usr/bin/apt-get ")));
    assert_eq!(calls.last().unwrap(), &format!("remove {unit}"));
    assert!(calls.contains(&"journal 0123456789abcdef0123456789abcdef".to_owned()));
}

#[test]
fn a_transient_unit_past_its_deadline_is_stopped_and_reported_timed_out() {
    let units = fake_units();
    *units.last.lock().unwrap() = status("active", "running", None, None);
    let registry = registry(
        vec![Fixed::new(
            "apply_package_updates",
            vec![program(
                "/usr/bin/apt-get",
                &["upgrade"],
                Privilege::PackageManager,
            )],
        )],
        units,
    );
    let ran = registry
        .run(
            &delivered("apply_package_updates", json!({}), 1),
            &TestControl::default(),
        )
        .unwrap();
    assert_eq!(ran.outcome, Outcome::TimedOut);
    let unit = format!("fleet-agent-task-{A}-1.service");
    assert!(units.calls().contains(&format!("stop {unit}")));
}

#[test]
fn a_unit_that_cannot_be_interrupted_is_left_running_when_the_agent_stops() {
    // DEC-16: never cut a package upgrade short; the next start waits for it (L8).
    let units = fake_units();
    *units.last.lock().unwrap() = status("active", "running", None, None);
    let registry = registry(
        vec![Fixed::new(
            "apply_package_updates",
            vec![program(
                "/usr/bin/apt-get",
                &["upgrade"],
                Privilege::PackageManager,
            )],
        )],
        units,
    );
    let control = TestControl::default();
    control.shutdown.request();
    control.cancel.set(true);
    assert_eq!(
        registry.run(
            &delivered("apply_package_updates", json!({}), 3600),
            &control
        ),
        None
    );
    assert!(
        !units
            .calls()
            .iter()
            .any(|c| c.starts_with("stop") || c.starts_with("remove"))
    );
}

#[test]
fn a_unit_that_cannot_start_is_an_agent_error() {
    let units = fake_units();
    units
        .fail_start
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let registry = registry(
        vec![Fixed::new(
            "apply_package_updates",
            vec![program(
                "/usr/bin/apt-get",
                &["upgrade"],
                Privilege::PackageManager,
            )],
        )],
        units,
    );
    let ran = registry
        .run(
            &delivered("apply_package_updates", json!({}), 3600),
            &TestControl::default(),
        )
        .unwrap();
    assert_eq!(ran.reason, Some("agent_error"));
    assert!(ran.output.contains("could not start fleet-agent-task-"));
}

fn ledger_task(task_type: &str) -> ledger::Task {
    ledger::Task {
        id: A.into(),
        task_type: Some(task_type.into()),
        state: ledger::State::Started,
        started: true,
        executed: true,
        started_at: Some("2026-01-01T12:00:00.000Z".into()),
        reported_at: None,
    }
}

#[test]
fn recovery_waits_for_a_running_unit_and_then_reports_what_it_did() {
    // Threat model L8.
    let units = fake_units();
    let registry = registry(
        vec![Fixed::new(
            "apply_package_updates",
            vec![program(
                "/usr/bin/apt-get",
                &["upgrade"],
                Privilege::PackageManager,
            )],
        )],
        units,
    );
    let missing = Status {
        load: "not-found".into(),
        ..Status::default()
    };
    // No unit at all: nothing to wait for.
    *units.last.lock().unwrap() = missing.clone();
    assert_eq!(
        registry.recover(&ledger_task("apply_package_updates")),
        Recovered::Nothing
    );
    // Step 1 still running.
    units
        .statuses
        .lock()
        .unwrap()
        .push_back(status("active", "running", None, None));
    assert_eq!(
        registry.recover(&ledger_task("apply_package_updates")),
        Recovered::Running
    );
    // Step 1 ended with 100.
    units
        .statuses
        .lock()
        .unwrap()
        .push_back(status("failed", "failed", Some(1), Some(100)));
    *units.journal.lock().unwrap() = "E: Could not get lock\n".into();
    let Recovered::Ended(ran) = registry.recover(&ledger_task("apply_package_updates")) else {
        panic!("not ended");
    };
    assert_eq!(
        (ran.outcome, ran.reason, ran.exit_status),
        (Outcome::Failed, Some("nonzero_exit"), Some(100))
    );
    assert!(ran.output.starts_with("E: Could not get lock\n"));
    assert!(
        ran.output
            .contains("the agent restarted while this task ran")
    );
    // A type this version does not run is never looked up.
    units.calls.lock().unwrap().clear();
    assert_eq!(
        registry.recover(&ledger_task("refresh_reports")),
        Recovered::Nothing
    );
    assert!(units.calls().is_empty());
}

#[test]
fn the_production_registry_implements_only_the_built_types() {
    // #36: refresh_reports and restart_service; anything else is refused with nothing run.
    let registry = Registry::production(
        TaskSettings::default(),
        Arc::new(crate::report::Refresh::new()),
    );
    let mut implemented = crate::tasks::IMPLEMENTED.to_vec();
    implemented.sort_unstable();
    assert_eq!(registry.ids(), implemented);
    for id in Catalog::embedded().unwrap().ids() {
        assert_eq!(registry.implements(id), implemented.contains(&id), "{id}");
    }
    assert!(registry.implements("refresh_reports"));
    assert!(registry.implements("restart_service"));
    assert!(
        registry
            .check(&delivered("refresh_reports", json!({}), 600))
            .is_ok()
    );
    let task = delivered("reboot", json!({}), 600);
    assert_eq!(registry.check(&task), Err("not_supported"));
    let ran = registry.run(&task, &TestControl::default()).unwrap();
    assert_eq!(
        (ran.outcome, ran.reason),
        (Outcome::Failed, Some("agent_error"))
    );
    assert!(ran.output.is_empty());
    // Neither type runs in a transient unit, so recovery asks systemd nothing about them.
    for id in ["refresh_reports", "restart_service"] {
        assert_eq!(registry.recover(&ledger_task(id)), Recovered::Nothing);
    }
}

#[test]
fn recovery_asks_about_units_only_for_a_package_manager_type() {
    let units = fake_units();
    *units.last.lock().unwrap() = status("active", "running", None, None);
    let registry = registry(
        vec![
            Fixed::new("refresh_reports", vec![]),
            Fixed::new("apply_package_updates", vec![]),
        ],
        units,
    );
    assert_eq!(
        registry.recover(&ledger_task("refresh_reports")),
        Recovered::Nothing
    );
    assert!(units.calls().is_empty());
    assert_eq!(
        registry.recover(&ledger_task("apply_package_updates")),
        Recovered::Running
    );
    assert!(!units.calls().is_empty());
}

// --- Privilege smoke (P3-A05): run as root on systemd, inside the agent unit's sandbox, by
// scripts/task-privilege-smoke.sh. Each proves one privilege works under the real unit.

#[test]
#[ignore = "needs root and systemd; run by scripts/task-privilege-smoke.sh"]
fn privilege_smoke_read_only_runs_inside_the_sandbox() {
    let ran = run_one(
        Fixed::new(
            "refresh_reports",
            vec![program("/usr/bin/env", &[], Privilege::ReadOnly)],
        ),
        json!({}),
        60,
        &TestControl::default(),
    );
    assert_eq!(ran.outcome, Outcome::Succeeded, "{}", ran.output);
    // And it cannot write outside the state directory (ProtectSystem=strict).
    let ran = run_one(
        Fixed::new(
            "refresh_reports",
            vec![program(
                "/usr/bin/touch",
                &["/usr/local/lib/fleet-agent-privsmoke-direct"],
                Privilege::ReadOnly,
            )],
        ),
        json!({}),
        60,
        &TestControl::default(),
    );
    assert_eq!(ran.outcome, Outcome::Failed, "{}", ran.output);
}

#[test]
#[ignore = "needs root and systemd; run by scripts/task-privilege-smoke.sh"]
fn privilege_smoke_service_manager_restarts_a_unit_from_inside_the_sandbox() {
    // The smoke script starts fleet-agent-privsmoke-dummy.service before running this.
    let invocation = || {
        let out = std::process::Command::new("/usr/bin/systemctl")
            .args([
                "show",
                "--property=InvocationID",
                "--value",
                "fleet-agent-privsmoke-dummy.service",
            ])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    let before = invocation();
    assert_eq!(before.len(), 32, "the dummy unit is not running");
    let restart = Fixed {
        type_id: "restart_service",
        programs: vec![program(
            "/usr/bin/systemctl",
            &["restart"],
            Privilege::ServiceManager,
        )],
        service: true,
    };
    let ran = run_one(
        restart,
        json!({"service": "fleet-agent-privsmoke-dummy.service"}),
        60,
        &TestControl::default(),
    );
    assert_eq!(ran.outcome, Outcome::Succeeded, "{}", ran.output);
    assert_ne!(invocation(), before, "the unit was not restarted");
}

fn real_units_registry(programs: Vec<Program>) -> Registry {
    Registry::new(
        vec![Box::new(Fixed::new("apply_package_updates", programs))],
        TaskSettings::default(),
        Box::new(unit::Systemd),
    )
}

#[test]
#[ignore = "needs root and systemd; run by scripts/task-privilege-smoke.sh"]
fn privilege_smoke_package_manager_runs_in_a_unit_that_can_write_usr() {
    let registry = real_units_registry(vec![
        program(
            "/usr/bin/touch",
            &["/usr/local/lib/fleet-agent-privsmoke-unit"],
            Privilege::PackageManager,
        ),
        program("/usr/bin/env", &[], Privilege::PackageManager),
    ]);
    let mut task = delivered("apply_package_updates", json!({}), 120);
    task.id = "00000000-0000-4000-8000-00000000a501".into();
    let ran = registry.run(&task, &TestControl::default()).unwrap();
    assert_eq!(ran.outcome, Outcome::Succeeded, "{}", ran.output);
    assert!(std::path::Path::new("/usr/local/lib/fleet-agent-privsmoke-unit").exists());
    for (key, value) in ENVIRONMENT {
        assert!(
            ran.output.contains(&format!("{key}={value}\n")),
            "{}",
            ran.output
        );
    }
}

#[test]
#[ignore = "needs root and systemd; run by scripts/task-privilege-smoke.sh"]
fn privilege_smoke_package_manager_unit_cannot_read_the_agents_credential() {
    // The smoke script writes /etc/fleet-agent/privsmoke-probe first.
    let registry = real_units_registry(vec![program(
        "/usr/bin/cat",
        &["/etc/fleet-agent/privsmoke-probe"],
        Privilege::PackageManager,
    )]);
    let mut task = delivered("apply_package_updates", json!({}), 120);
    task.id = "00000000-0000-4000-8000-00000000a502".into();
    let ran = registry.run(&task, &TestControl::default()).unwrap();
    assert_eq!(ran.outcome, Outcome::Failed, "{}", ran.output);
    assert!(!ran.output.contains("privsmoke-secret"), "{}", ran.output);
}

#[test]
#[ignore = "needs root and systemd; run by scripts/task-privilege-smoke.sh"]
fn privilege_smoke_package_manager_unit_is_stopped_at_its_deadline() {
    let registry = real_units_registry(vec![program(
        "/usr/bin/sleep",
        &["600"],
        Privilege::PackageManager,
    )]);
    let mut task = delivered("apply_package_updates", json!({}), 3);
    task.id = "00000000-0000-4000-8000-00000000a503".into();
    let ran = registry.run(&task, &TestControl::default()).unwrap();
    assert_eq!(ran.outcome, Outcome::TimedOut, "{}", ran.output);
    let status = unit::Systemd
        .status(&Generated::task_unit(&task.id, 1).unwrap())
        .unwrap();
    assert!(status.missing() || !status.running(), "{status:?}");
}
