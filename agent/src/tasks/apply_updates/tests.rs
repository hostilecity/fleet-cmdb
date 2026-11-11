//! `apply_package_updates` with a fake apt: the transient units are scripted ([`FakeApt`], which
//! answers each fixed apt-get or needrestart vector with an exit status and output), and so is the host
//! ([`FakeHost`]: installed packages, files, locks). Nothing here runs a package manager.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use super::*;
use crate::tasks::catalog::Catalog;
use crate::tasks::executor::output::Capture;
use crate::tasks::executor::spawn::Generated;
use crate::tasks::executor::tests::{A, TestControl, delivered};
use crate::tasks::executor::unit::{Status, Units};
use crate::tasks::executor::{Executor, Recovered, Registry};
use crate::tasks::ledger;

const UPDATE: &str = "update";
const UPGRADE: &str = "upgrade";
const SIMULATE: &str = "simulate";
const NEEDRESTART: &str = "needrestart";

fn key(program: &Program) -> &'static str {
    if program.path == apt::NEEDRESTART {
        NEEDRESTART
    } else if program.args.contains(&"--simulate") {
        SIMULATE
    } else if program.args.last() == Some(&"update") {
        UPDATE
    } else {
        UPGRADE
    }
}

/// Scripted systemd running a scripted apt: each step's unit ends at once with the reply set for its
/// program, or never ends (`hang`) until stopped.
#[derive(Default)]
struct FakeApt {
    replies: Mutex<HashMap<&'static str, (i32, String)>>,
    hang: Mutex<HashSet<&'static str>>,
    /// unit name -> (program key, invocation number)
    units: Mutex<HashMap<String, (&'static str, u32)>>,
    stopped: Mutex<HashSet<String>>,
    started: Mutex<Vec<(String, &'static str)>>,
    next: AtomicU32,
}

impl FakeApt {
    fn reply(&self, key: &'static str, status: i32, output: &str) {
        self.replies
            .lock()
            .unwrap()
            .insert(key, (status, output.to_owned()));
    }

    /// The programs started, in order.
    fn started(&self) -> Vec<&'static str> {
        self.started
            .lock()
            .unwrap()
            .iter()
            .map(|(_, k)| *k)
            .collect()
    }

    fn unit_names(&self) -> Vec<String> {
        self.started
            .lock()
            .unwrap()
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }
}

fn exited(code: i32, invocation: u32) -> Status {
    Status {
        load: "loaded".into(),
        active: "active".into(),
        sub: "exited".into(),
        result: if code == 0 { "success" } else { "exit-code" }.into(),
        main_code: Some(1),
        main_status: Some(code),
        invocation: format!("{invocation:032x}"),
    }
}

impl Units for FakeApt {
    fn start(&self, name: &Generated, program: &Program, _: u64) -> Result<(), String> {
        let key = key(program);
        let n = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        self.units
            .lock()
            .unwrap()
            .insert(name.as_str().to_owned(), (key, n));
        self.started
            .lock()
            .unwrap()
            .push((name.as_str().to_owned(), key));
        Ok(())
    }

    fn status(&self, name: &Generated) -> Result<Status, String> {
        let Some((key, n)) = self.units.lock().unwrap().get(name.as_str()).copied() else {
            return Ok(Status {
                load: "not-found".into(),
                ..Status::default()
            });
        };
        if self.stopped.lock().unwrap().contains(name.as_str()) {
            return Ok(Status {
                load: "loaded".into(),
                active: "failed".into(),
                sub: "failed".into(),
                result: "signal".into(),
                main_code: Some(2),
                main_status: Some(15),
                invocation: format!("{n:032x}"),
            });
        }
        if self.hang.lock().unwrap().contains(key) {
            return Ok(Status {
                load: "loaded".into(),
                active: "active".into(),
                sub: "running".into(),
                invocation: format!("{n:032x}"),
                ..Status::default()
            });
        }
        let code = self
            .replies
            .lock()
            .unwrap()
            .get(key)
            .map_or(0, |(code, _)| *code);
        Ok(exited(code, n))
    }

    fn stop(&self, name: &Generated) -> Result<(), String> {
        self.stopped
            .lock()
            .unwrap()
            .insert(name.as_str().to_owned());
        Ok(())
    }

    fn journal(&self, invocation: &str, capture: &Arc<Mutex<Capture>>) -> Result<(), String> {
        let units = self.units.lock().unwrap();
        let key = units
            .values()
            .find(|(_, n)| format!("{n:032x}") == invocation)
            .map(|(k, _)| *k)
            .ok_or("no such invocation")?;
        let output = self
            .replies
            .lock()
            .unwrap()
            .get(key)
            .map(|(_, o)| o.clone())
            .unwrap_or_default();
        capture.lock().unwrap().push(output.as_bytes());
        Ok(())
    }

    fn remove(&self, name: &Generated) {
        self.units.lock().unwrap().remove(name.as_str());
    }
}

struct SharedApt(&'static FakeApt);

impl Units for SharedApt {
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

/// A scripted host.
#[derive(Default)]
struct FakeHost {
    /// Each listing in turn (before, after); `Err` when used up.
    listings: Mutex<VecDeque<Result<BTreeMap<String, String>, String>>>,
    files: Mutex<HashSet<String>>,
    /// How many more lock checks find a lock held.
    held_for: AtomicU32,
    lock_checks: AtomicU32,
}

impl FakeHost {
    fn debian() -> Self {
        let host = Self::default();
        for file in ["/usr/bin/apt-get", "/var/lib/dpkg/status", apt::NEEDRESTART] {
            host.add(file);
        }
        host
    }

    fn add(&self, path: &str) {
        self.files.lock().unwrap().insert(path.to_owned());
    }

    fn remove(&self, path: &str) {
        self.files.lock().unwrap().remove(path);
    }

    fn listing(&self, packages: &[(&str, &str)]) {
        self.listings.lock().unwrap().push_back(Ok(packages
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()));
    }
}

impl System for FakeHost {
    fn installed(&self, _: &Shutdown) -> Result<BTreeMap<String, String>, String> {
        self.listings
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err("dpkg-query failed".into()))
    }

    fn exists(&self, path: &str) -> bool {
        self.files.lock().unwrap().contains(path)
    }

    fn locked(&self, _: &str) -> bool {
        self.lock_checks.fetch_add(1, Ordering::SeqCst);
        self.held_for
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
    }
}

#[derive(Default)]
struct Reports(AtomicU32);

impl PackageReport for Reports {
    fn request_package_report(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct Rig {
    apt: &'static FakeApt,
    host: Arc<FakeHost>,
    reports: Arc<Reports>,
    registry: Registry,
}

fn rig_with(host: FakeHost, lock_wait: Duration) -> Rig {
    let apt: &'static FakeApt = Box::leak(Box::default());
    let host = Arc::new(host);
    let reports = Arc::new(Reports::default());
    let task = ApplyUpdates::new(
        Arc::new(apt::Apt),
        Arc::clone(&host) as Arc<dyn System>,
        Arc::clone(&reports) as Arc<dyn PackageReport>,
        lock_wait,
    );
    let registry = Registry::new(
        vec![Box::new(task)],
        TaskSettings::default(),
        Box::new(SharedApt(apt)),
    );
    Rig {
        apt,
        host,
        reports,
        registry,
    }
}

fn debian() -> Rig {
    rig_with(FakeHost::debian(), Duration::from_millis(200))
}

impl Rig {
    fn run(
        &self,
        timeout: u64,
        control: &TestControl,
    ) -> Option<crate::tasks::executor::Execution> {
        self.registry
            .run(&delivered(TYPE_ID, json!({}), timeout), control)
    }

    fn reports(&self) -> u32 {
        self.reports.0.load(Ordering::SeqCst)
    }
}

const SIMULATED: &str = "Inst acme-held [1.0-1] (1.1-1 example.lan [amd64])\nInst acme-new (1.0 example.lan [amd64])\nInst acme-needsnew [2.0] (2.1 example.lan [all])\n";

#[test]
fn a_clean_upgrade_succeeds_reports_what_changed_and_asks_for_a_package_report() {
    let rig = debian();
    rig.host.listing(&[
        ("curl:amd64", "8.14.1-2"),
        ("tzdata:all", "2025a-1"),
        ("acme-held:amd64", "1.0-1"),
        ("libfoo1:i386", "2.0"),
    ]);
    rig.host.listing(&[
        ("curl:amd64", "8.14.1-2+deb13u1"),
        ("tzdata:all", "2025b-1"),
        ("acme-held:amd64", "1.0-1"),
        ("libfoo1:i386", "2.1"),
    ]);
    rig.apt.reply(
        UPDATE,
        0,
        "Hit:1 http://deb.example.lan/debian trixie InRelease\n",
    );
    rig.apt.reply(
        UPGRADE,
        0,
        "Unpacking curl (8.14.1-2+deb13u1) over (8.14.1-2) ...\n3 upgraded, 0 newly installed, 0 to remove and 2 not upgraded.\n",
    );
    rig.apt.reply(SIMULATE, 0, SIMULATED);
    rig.apt.reply(
        NEEDRESTART,
        0,
        "NEEDRESTART-KSTA: 1\nNEEDRESTART-SVC: nginx.service\nNEEDRESTART-SVC: cron.service\n",
    );
    let control = TestControl::default();
    let ran = rig.run(3600, &control).unwrap();
    assert_eq!(
        (ran.outcome, ran.reason, ran.exit_status),
        (Outcome::Succeeded, None, Some(0)),
        "{}",
        ran.output
    );
    // The fixed steps, in order, each in its own unit.
    assert_eq!(rig.apt.started(), [UPDATE, UPGRADE, SIMULATE, NEEDRESTART]);
    assert_eq!(
        rig.apt.unit_names(),
        (1..=4)
            .map(|n| format!("fleet-agent-task-{A}-{n}.service"))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        Value::Object(ran.details.clone()),
        json!({
            "reboot_required": false,
            "packages_upgraded": 3,
            "packages_held_back": ["acme-held", "acme-needsnew"],
            "services_needing_restart": ["cron.service", "nginx.service"],
        })
    );
    // Each step's output follows the agent's `$` line, and the summary comes last.
    let update_at = ran
        .output
        .find("$ /usr/bin/apt-get -q --error-on=any -o DPkg::Lock::Timeout=300 update\nHit:1")
        .expect(&ran.output);
    let upgrade_at = ran
        .output
        .find("$ /usr/bin/apt-get -q -y -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o APT::Get::Upgrade-Allow-New=false --no-remove upgrade\nUnpacking curl")
        .expect(&ran.output);
    assert!(update_at < upgrade_at);
    assert!(ran.output.contains("$ /usr/sbin/needrestart -b -r l\n"));
    assert!(
        ran.output
            .contains("[fleet-agent: 3 packages upgraded: curl, libfoo1:i386, tzdata]")
    );
    assert!(ran.output.contains("2 packages held back"));
    assert!(ran.output.contains("[fleet-agent: no reboot required]"));
    assert!(ran.output.contains(
        "services using old code, not restarted (the task never restarts services): cron.service, nginx.service"
    ));
    assert_eq!(rig.reports(), 1);
    // What the agent sends conforms to the result contract, details included.
    let body = crate::tasks::wire::result_body(&crate::tasks::wire::ResultFields {
        outcome: ran.outcome,
        reason: ran.reason,
        exit_status: ran.exit_status,
        started_at: Some(crate::report::rfc3339(ran.started_at)),
        finished_at: crate::report::rfc3339(ran.finished_at),
        output: ran.output.clone(),
        output_truncated: ran.output_truncated,
        details: ran.details.clone(),
    });
    crate::collect::contract::assert_conforms("v1", "task-result.request", &body);
}

#[test]
fn reboot_required_comes_from_the_flag_file_a_kernel_upgrade_or_needrestart() {
    for case in ["flag", "kernel", "needrestart", "none"] {
        let rig = debian();
        let (before, after) = if case == "kernel" {
            ("6.12.37-1", "6.12.38-1")
        } else {
            ("1.0", "1.0")
        };
        rig.host
            .listing(&[("linux-image-6.12.0-9-amd64:amd64", before)]);
        rig.host
            .listing(&[("linux-image-6.12.0-9-amd64:amd64", after)]);
        if case == "flag" {
            rig.host.add(apt::REBOOT_FLAG);
        }
        rig.apt.reply(
            NEEDRESTART,
            0,
            if case == "needrestart" {
                "NEEDRESTART-KSTA: 3\n"
            } else {
                "NEEDRESTART-KSTA: 1\n"
            },
        );
        let ran = rig.run(3600, &TestControl::default()).unwrap();
        assert_eq!(ran.outcome, Outcome::Succeeded, "{case}: {}", ran.output);
        assert_eq!(
            ran.details["reboot_required"],
            json!(case != "none"),
            "{case}"
        );
        if case != "none" {
            assert!(
                ran.output.contains("reboot required (")
                    && ran.output.contains("the task never reboots"),
                "{case}: {}",
                ran.output
            );
        }
    }
}

#[test]
fn without_needrestart_services_are_not_reported_and_the_rest_still_is() {
    let rig = debian();
    rig.host.remove(apt::NEEDRESTART);
    rig.host.listing(&[("a:amd64", "1")]);
    rig.host.listing(&[("a:amd64", "1")]);
    let ran = rig.run(3600, &TestControl::default()).unwrap();
    assert_eq!(ran.outcome, Outcome::Succeeded, "{}", ran.output);
    assert_eq!(rig.apt.started(), [UPDATE, UPGRADE, SIMULATE]);
    assert!(!ran.details.contains_key("services_needing_restart"));
    assert_eq!(ran.details["packages_upgraded"], json!(0));
    assert_eq!(ran.details["packages_held_back"], json!([]));
    assert!(ran.output.contains("needrestart is not installed"));
    assert!(
        ran.output
            .contains("[fleet-agent: no package was upgraded]")
    );
}

#[test]
fn a_listing_or_a_simulation_that_fails_leaves_its_detail_out_but_not_the_upgrade() {
    let rig = debian();
    // No listing at all, and the simulation and restart check fail.
    rig.apt.reply(SIMULATE, 100, "E: something\n");
    rig.apt.reply(NEEDRESTART, 1, "");
    let ran = rig.run(3600, &TestControl::default()).unwrap();
    assert_eq!(ran.outcome, Outcome::Succeeded, "{}", ran.output);
    assert_eq!(
        Value::Object(ran.details.clone()),
        json!({"reboot_required": false})
    );
    assert!(
        ran.output
            .contains("the installed packages could not be listed")
    );
    assert!(
        ran.output
            .contains("which packages were held back is not known")
    );
    assert!(ran.output.contains("the restart check failed"));
}

#[test]
fn a_lock_held_past_the_wait_fails_lock_timeout_with_nothing_run() {
    let host = FakeHost::debian();
    host.held_for.store(u32::MAX, Ordering::SeqCst);
    let rig = rig_with(host, Duration::from_millis(300));
    let started = Instant::now();
    let ran = rig.run(3600, &TestControl::default()).unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(
        (ran.outcome, ran.reason),
        (Outcome::Failed, Some("lock_timeout")),
        "{}",
        ran.output
    );
    assert!(rig.apt.started().is_empty());
    assert_eq!(rig.reports(), 0);
    assert!(ran.output.contains(
        "another program holds /var/lib/dpkg/lock-frontend; waiting up to 0 seconds for it"
    ));
    assert!(ran.output.contains("the package manager is busy"));
    assert!(ran.output.contains("nothing was upgraded"));
}

#[test]
fn a_lock_released_during_the_wait_lets_the_task_run() {
    let host = FakeHost::debian();
    host.held_for.store(1, Ordering::SeqCst);
    let rig = rig_with(host, Duration::from_secs(30));
    let ran = rig.run(3600, &TestControl::default()).unwrap();
    assert_eq!(ran.outcome, Outcome::Succeeded, "{}", ran.output);
    assert!(rig.host.lock_checks.load(Ordering::SeqCst) >= 2);
    assert!(ran.output.contains("waiting up to 30 seconds"));
}

#[test]
fn a_lock_taken_by_another_program_during_a_step_is_lock_timeout() {
    for (step, message) in [
        (
            UPDATE,
            "E: Could not get lock /var/lib/apt/lists/lock. It is held by process 4242 (apt-get)\nE: Unable to lock directory /var/lib/apt/lists/\n",
        ),
        (
            UPGRADE,
            "Waiting for cache lock: Could not get lock /var/lib/dpkg/lock-frontend.\nE: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), is another process using it?\n",
        ),
    ] {
        let rig = debian();
        rig.apt.reply(step, 100, message);
        let ran = rig.run(3600, &TestControl::default()).unwrap();
        assert_eq!(
            (ran.outcome, ran.reason, ran.exit_status),
            (Outcome::Failed, Some("lock_timeout"), Some(100)),
            "{step}: {}",
            ran.output
        );
        assert_eq!(
            rig.apt.started().last(),
            Some(&step),
            "nothing runs after it"
        );
        assert!(
            ran.output
                .contains("another program held the package manager's lock")
        );
        // Refused for a lock, nothing was changed: no repair is needed.
        assert!(!ran.output.contains("dpkg --configure -a"), "{step}");
        // A package report only once the upgrade began.
        assert_eq!(rig.reports(), u32::from(step == UPGRADE));
    }
}

#[test]
fn a_failed_upgrade_is_nonzero_exit_with_the_repair_guidance() {
    let rig = debian();
    rig.apt.reply(
        UPGRADE,
        100,
        "dpkg: error processing package acme (--configure):\nE: Sub-process /usr/bin/dpkg returned an error code (1)\n",
    );
    let ran = rig.run(3600, &TestControl::default()).unwrap();
    assert_eq!(
        (ran.outcome, ran.reason, ran.exit_status),
        (Outcome::Failed, Some("nonzero_exit"), Some(100))
    );
    assert!(ran.output.contains("run dpkg --configure -a as root"));
    assert_eq!(rig.apt.started(), [UPDATE, UPGRADE]);
    assert_eq!(rig.reports(), 1);

    // An update refused because dpkg was interrupted earlier says how to repair it too.
    let rig = debian();
    rig.apt.reply(
        UPDATE,
        100,
        "E: dpkg was interrupted, you must manually run 'dpkg --configure -a' to correct the problem.\n",
    );
    let ran = rig.run(3600, &TestControl::default()).unwrap();
    assert_eq!(ran.reason, Some("nonzero_exit"));
    assert!(ran.output.contains("run dpkg --configure -a as root"));
    assert_eq!(rig.apt.started(), [UPDATE]);
    assert_eq!(rig.reports(), 0);

    // A failed update with no such message needs no repair.
    let rig = debian();
    rig.apt.reply(
        UPDATE,
        100,
        "E: Failed to fetch http://deb.example.lan/debian/dists/trixie/InRelease\n",
    );
    let ran = rig.run(3600, &TestControl::default()).unwrap();
    assert_eq!(ran.reason, Some("nonzero_exit"));
    assert!(!ran.output.contains("dpkg --configure -a"));
}

#[test]
fn an_upgrade_past_the_deadline_is_stopped_and_timed_out_with_the_repair_guidance() {
    let rig = debian();
    rig.apt.hang.lock().unwrap().insert(UPGRADE);
    rig.apt.reply(UPGRADE, 0, "Setting up acme (1.1) ...\n");
    let ran = rig.run(2, &TestControl::default()).unwrap();
    assert_eq!(ran.outcome, Outcome::TimedOut, "{}", ran.output);
    assert!(
        rig.apt
            .stopped
            .lock()
            .unwrap()
            .contains(&format!("fleet-agent-task-{A}-2.service"))
    );
    assert!(ran.output.contains("Setting up acme (1.1) ...\n"));
    assert!(
        ran.output
            .contains("the package database may need repair: run dpkg --configure -a")
    );
    assert!(ran.output.contains("ran past its deadline of 2 seconds"));
    assert_eq!(rig.reports(), 1);
}

#[test]
fn a_cancel_never_stops_it() {
    let rig = debian();
    let control = TestControl::default();
    control.cancel.set(true);
    let ran = rig.run(3600, &control).unwrap();
    assert_eq!(ran.outcome, Outcome::Succeeded, "{}", ran.output);
    assert_eq!(rig.apt.started(), [UPDATE, UPGRADE, SIMULATE, NEEDRESTART]);
}

#[test]
fn the_agent_stopping_mid_upgrade_leaves_it_running_in_its_unit() {
    let rig = debian();
    rig.apt.hang.lock().unwrap().insert(UPGRADE);
    let control = TestControl::default();
    control.shutdown.request();
    assert!(rig.run(3600, &control).is_none());
    assert!(rig.apt.stopped.lock().unwrap().is_empty());
    assert_eq!(rig.apt.started(), [UPDATE, UPGRADE]);
}

#[test]
fn the_agent_stopping_during_the_lock_wait_is_interrupted_with_nothing_run() {
    let host = FakeHost::debian();
    host.held_for.store(u32::MAX, Ordering::SeqCst);
    let rig = rig_with(host, Duration::from_secs(60));
    let control = TestControl::default();
    control.shutdown.request();
    let ran = rig.run(3600, &control).unwrap();
    assert_eq!(
        (ran.outcome, ran.reason),
        (Outcome::Failed, Some("interrupted"))
    );
    assert!(rig.apt.started().is_empty());
}

// --- Refused runs nothing ---------------------------------------------------------------------------

#[test]
fn bad_parameters_or_a_host_without_apt_are_refused_with_nothing_run() {
    let rig = debian();
    for params in [
        json!({"scope": "security"}),
        json!({"packages": ["openssl"]}),
        json!({"options": "--allow-downgrades"}),
        json!([]),
        json!("upgrade"),
        Value::Null,
    ] {
        let task = delivered(TYPE_ID, params.clone(), 3600);
        assert_eq!(rig.registry.check(&task), Err("invalid_params"), "{params}");
        // Even if run were reached, it would run nothing.
        let ran = rig.registry.run(&task, &TestControl::default()).unwrap();
        assert_eq!(
            (ran.outcome, ran.reason),
            (Outcome::Failed, Some("agent_error"))
        );
    }
    let host = FakeHost::debian();
    host.remove("/usr/bin/apt-get");
    let no_apt = rig_with(host, Duration::from_millis(1));
    assert_eq!(
        no_apt.registry.check(&delivered(TYPE_ID, json!({}), 3600)),
        Err("not_supported")
    );
    for rig in [&rig, &no_apt] {
        assert!(rig.apt.started().is_empty());
        assert_eq!(rig.host.lock_checks.load(Ordering::SeqCst), 0);
        assert_eq!(rig.reports(), 0);
    }
    assert_eq!(
        rig.registry.check(&delivered(TYPE_ID, json!({}), 3600)),
        Ok(())
    );
}

#[test]
fn the_parameters_match_the_catalogs_closed_empty_schema() {
    let entry = Catalog::embedded().unwrap().get(TYPE_ID).unwrap();
    assert_eq!(entry.parameters["properties"], json!({}));
    assert_eq!(entry.parameters["additionalProperties"], json!(false));
    assert!(!entry.interruptible);
    assert_eq!(entry.timeout_seconds, 3600);
    assert!(!entry.on_by_default());
}

// --- Recovery after an agent restart (threat model L8) ------------------------------------------------

fn ledger_task() -> ledger::Task {
    ledger::Task {
        id: A.into(),
        task_type: Some(TYPE_ID.into()),
        state: ledger::State::Started,
        started: true,
        executed: true,
        started_at: Some("2026-01-01T12:00:00.000Z".into()),
        reported_at: None,
    }
}

/// Leaves units for the given steps, as an agent stopped mid-task would.
fn left(rig: &Rig, steps: &[(u32, &'static str)]) {
    for (step, key) in steps {
        let name = Generated::task_unit(A, *step).unwrap();
        rig.apt.start(&name, &apt::Apt.refresh_for(key), 1).unwrap();
    }
}

impl apt::Apt {
    fn refresh_for(&self, key: &str) -> Program {
        match key {
            UPDATE => self.refresh(),
            UPGRADE => self.upgrade(),
            SIMULATE => self.pending(),
            _ => self.restart_check(&FakeHost::debian()).unwrap(),
        }
    }
}

fn recovered(rig: &Rig) -> crate::tasks::executor::Execution {
    match rig.registry.recover(&ledger_task()) {
        Recovered::Ended(ran) => ran,
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_recovered_upgrade_that_ended_with_0_succeeded() {
    for steps in [
        vec![(UPGRADE_STEP, UPGRADE)],
        vec![(1, UPDATE), (2, UPGRADE)],
        // The upgrade was collected before the agent stopped; a later step exists only after a success.
        vec![(3, SIMULATE)],
        vec![(4, NEEDRESTART)],
    ] {
        let rig = debian();
        rig.host.add(apt::REBOOT_FLAG);
        rig.apt.reply(UPGRADE, 0, "Setting up acme (1.1) ...\n");
        left(&rig, &steps);
        let ran = recovered(&rig);
        assert_eq!(
            (ran.outcome, ran.reason, ran.exit_status),
            (Outcome::Succeeded, None, Some(0)),
            "{steps:?}: {}",
            ran.output
        );
        assert_eq!(Value::Object(ran.details), json!({"reboot_required": true}));
        assert!(
            ran.output
                .contains("the upgrade finished while the agent was restarting")
        );
        assert!(ran.output.contains("reboot required: yes"));
        assert_eq!(rig.reports(), 1, "{steps:?}");
    }
}

#[test]
fn a_recovered_failure_keeps_its_reason() {
    let rig = debian();
    rig.apt.reply(
        UPGRADE,
        100,
        "E: Could not get lock /var/lib/dpkg/lock-frontend\n",
    );
    left(&rig, &[(2, UPGRADE)]);
    let ran = recovered(&rig);
    assert_eq!(
        (ran.outcome, ran.reason, ran.exit_status),
        (Outcome::Failed, Some("lock_timeout"), Some(100))
    );
    assert!(!ran.output.contains("dpkg --configure -a"));

    let rig = debian();
    rig.apt.reply(
        UPGRADE,
        1,
        "E: Sub-process /usr/bin/dpkg returned an error code (1)\n",
    );
    left(&rig, &[(2, UPGRADE)]);
    let ran = recovered(&rig);
    assert_eq!(
        (ran.outcome, ran.reason),
        (Outcome::Failed, Some("nonzero_exit"))
    );
    assert_eq!(rig.reports(), 1);
}

#[test]
fn a_recovered_task_that_only_refreshed_the_index_is_interrupted() {
    let rig = debian();
    left(&rig, &[(1, UPDATE)]);
    let ran = recovered(&rig);
    assert_eq!(
        (ran.outcome, ran.reason),
        (Outcome::Failed, Some("interrupted"))
    );
    assert_eq!(rig.reports(), 0);
}

#[test]
fn a_recovered_upgrade_that_reached_its_limit_is_timed_out_with_the_repair_guidance() {
    // The framework reports `timed_out` (the hook returns None); the hook adds the repair guidance
    // and asks for a package report. A timed-out refresh alone needs neither.
    let rig = debian();
    let task = ApplyUpdates::new(
        Arc::new(apt::Apt),
        Arc::clone(&rig.host) as Arc<dyn System>,
        Arc::clone(&rig.reports) as Arc<dyn PackageReport>,
        LOCK_WAIT,
    );
    let killed = Exit {
        code: None,
        signal: Some(9),
    };
    let mut notes = Vec::new();
    assert!(
        task.recovered(&[(2, killed)], true, "", &mut notes)
            .is_none()
    );
    assert_eq!(notes.len(), 1);
    assert!(notes[0].contains("dpkg --configure -a"));
    assert_eq!(rig.reports(), 1);
    let mut notes = Vec::new();
    assert!(
        task.recovered(&[(1, killed)], true, "", &mut notes)
            .is_none()
    );
    assert!(notes.is_empty());
    assert_eq!(rig.reports(), 1);
}

// --- The host ---------------------------------------------------------------------------------------

#[test]
fn a_lock_held_by_another_process_is_seen_and_a_free_one_is_not() {
    let dir = crate::test_support::TempDir::new();
    let path = dir.write("lock-frontend", "");
    let file = std::fs::File::open(&path).unwrap();
    assert!(!lock_held(&file));
    assert!(!RealSystem.locked(path.to_str().unwrap()));
    assert!(!RealSystem.locked("/nonexistent/fleet-agent-test-lock"));

    // A child process takes a write lock, as apt does, and waits to be killed.
    let (mut ready, writer) = std::io::pipe().unwrap();
    let held = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    // SAFETY: the child only calls async-signal-safe functions (fcntl, write, pause) before it is killed.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        use std::os::fd::AsRawFd;
        unsafe {
            let mut lock: libc::flock = std::mem::zeroed();
            lock.l_type = libc::F_WRLCK as libc::c_short;
            lock.l_whence = libc::SEEK_SET as libc::c_short;
            libc::fcntl(held.as_raw_fd(), libc::F_SETLK, &lock);
            libc::write(writer.as_raw_fd(), b"x".as_ptr().cast(), 1);
            loop {
                libc::pause();
            }
        }
    }
    drop(writer);
    let mut byte = [0u8; 1];
    std::io::Read::read_exact(&mut ready, &mut byte).unwrap();
    let seen = lock_held(&file) && RealSystem.locked(path.to_str().unwrap());
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
    assert!(seen, "the child's lock was not seen");
    assert!(!lock_held(&file));
}

#[test]
fn summaries_name_a_bounded_number_of_packages() {
    let names: Vec<String> = (0..45).map(|n| format!("pkg{n}")).collect();
    let text = listed(&names);
    assert!(text.starts_with("pkg0, pkg1"));
    assert!(text.ends_with(", and 5 more"));
    assert_eq!(count(1, "package"), "1 package");
    assert_eq!(count(2, "package"), "2 packages");
    assert_eq!(display_name("tzdata:all"), "tzdata");
    assert_eq!(display_name(&format!("curl:{}", native_arch())), "curl");
    assert_eq!(display_name("libfoo1:s390x"), "libfoo1:s390x");
}

// --- Privilege smoke (P3-A05): run as root on systemd, inside the agent unit's sandbox, by
// scripts/task-privilege-smoke.sh.

#[test]
#[ignore = "needs root and systemd; run by scripts/task-privilege-smoke.sh"]
fn privilege_smoke_apt_simulation_runs_in_a_task_unit() {
    // The task's own fixed vector, in a real transient unit with the real properties: apt reads its
    // lists and the dpkg database outside the sandbox. A simulation, so the runner is not upgraded;
    // the real upgrade is in scripts/vm-test.sh.
    let registry = Registry::new(
        vec![Box::new(crate::tasks::executor::tests::Fixed::new(
            TYPE_ID,
            vec![apt::Apt.pending()],
        ))],
        TaskSettings::default(),
        Box::new(crate::tasks::executor::unit::Systemd),
    );
    let mut task = delivered(TYPE_ID, json!({}), 300);
    task.id = "00000000-0000-4000-8000-00000000a504".into();
    let ran = registry.run(&task, &TestControl::default()).unwrap();
    assert_eq!(ran.outcome, Outcome::Succeeded, "{}", ran.output);
    assert!(ran.output.contains("Calculating upgrade"), "{}", ran.output);
}

#[test]
#[ignore = "needs root and systemd; run by scripts/task-privilege-smoke.sh"]
fn privilege_smoke_the_lock_check_and_the_listing_work_inside_the_sandbox() {
    // The smoke script holds /var/lib/dpkg/lock-frontend from another process, as apt would, for
    // the length of this run. The agent's file system is read-only: F_GETLK must still see it.
    assert!(
        RealSystem.locked(apt::LOCKS[0]),
        "the held frontend lock was not seen"
    );
    let installed = RealSystem.installed(&Shutdown::default()).unwrap();
    assert!(installed.len() > 50, "{} packages", installed.len());
    assert!(apt::Apt.present(&RealSystem));
}
