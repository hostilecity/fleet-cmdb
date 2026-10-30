//! Inventory reporter tests with a scripted transport and simulated time.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::fs;

use serde_json::json;

use super::*;
use crate::collect::contract::assert_conforms;
use crate::collect::{Disk, NetworkInterface, OsRelease};
use crate::config::Interval;
use crate::logging::capture::logs_of;
use crate::report::tests::{FakeTransport, ok};
use crate::retry::{RetryPolicy, SplitMix64};
use crate::test_support::TempDir;

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn intervals() -> Intervals {
    Intervals::new(
        Interval {
            start: secs(60),
            min: secs(30),
            max: secs(600),
        },
        Interval {
            start: secs(900),
            min: secs(300),
            max: secs(21_600),
        },
    )
}

fn sample() -> Inventory {
    Inventory {
        hostname: Some("vm-01.example.lan".into()),
        os: Some(OsRelease {
            id: Some("debian".into()),
            version_id: Some("13".into()),
            pretty_name: Some("Debian GNU/Linux 13 (trixie)".into()),
        }),
        kernel_version: Some("6.12.38+deb13-amd64".into()),
        architecture: Some("x86_64".into()),
        cpu_model: Some("QEMU Virtual CPU version 2.5+".into()),
        cpu_cores: Some(2),
        memory_total_bytes: Some(4_000_000_000),
        memory_available_bytes: Some(3_000_000_000),
        uptime_seconds: Some(3600),
        boot_id: Some("00000000-0000-4000-8000-000000000002".into()),
        machine_id: Some("0123456789abcdef0123456789abcdef".into()),
        disks: Some(vec![Disk {
            mount: "/".into(),
            filesystem: "ext4".into(),
            size_bytes: 20_000_000_000,
            free_bytes: 10_000_000_000,
        }]),
        network_interfaces: Some(vec![NetworkInterface {
            name: "ens18".into(),
            primary: true,
            addresses: vec!["192.0.2.10/24".into()],
        }]),
        warnings: vec![],
    }
}

/// The server's reply to an inventory report it accepted.
fn accepted(body: &serde_json::Value) -> Result<crate::client::ApiResponse, ApiError> {
    ok(json!({"report_id": body["report_id"], "duplicate": false}))
}

/// A reporter, its state directory, simulated time, and the facts it collects.
struct Harness {
    dir: TempDir,
    intervals: Intervals,
    facts: RefCell<Inventory>,
    collections: Cell<usize>,
    start: Instant,
}

impl Harness {
    fn new() -> Self {
        let dir = TempDir::new();
        crate::state::ensure_dir(&dir.path("state")).unwrap();
        Self {
            dir,
            intervals: intervals(),
            facts: RefCell::new(sample()),
            collections: Cell::new(0),
            start: Instant::now(),
        }
    }

    fn state_dir(&self) -> PathBuf {
        self.dir.path("state")
    }

    fn reporter(&self) -> Reporter<'_, SplitMix64> {
        Reporter::new(
            &self.intervals,
            self.state_dir(),
            Backoff::new(RetryPolicy::default(), SplitMix64::new(7)),
            SplitMix64::new(8),
        )
    }

    fn at(&self, offset: Duration) -> Instant {
        self.start + secs(1) + offset
    }

    fn tick(
        &self,
        reporter: &mut Reporter<'_, SplitMix64>,
        transport: &FakeTransport,
        now: Instant,
    ) -> Instant {
        let mut collect = || {
            self.collections.set(self.collections.get() + 1);
            self.facts.borrow().clone()
        };
        let wake = reporter.tick(now, &mut collect, transport);
        assert!(wake > now, "tick asked to be called again at once");
        wake
    }

    /// Runs the loop from `from` until simulated time `until`, waking when the reporter asks. The
    /// server accepts every request the script does not answer if `accept`, and is down otherwise.
    /// Returns the time reached.
    fn drive(
        &self,
        reporter: &mut Reporter<'_, SplitMix64>,
        transport: &FakeTransport,
        from: Instant,
        until: Duration,
        accept: bool,
    ) -> Instant {
        transport.set_accepting(accept);
        let mut now = from;
        while now < self.at(until) {
            now = self.tick(reporter, transport, now);
        }
        now
    }

    fn record(&self) -> Option<Record> {
        fs::read(self.state_dir().join(RECORD_NAME))
            .ok()
            .map(|b| serde_json::from_slice(&b).unwrap())
    }
}

fn ids(transport: &FakeTransport) -> Vec<String> {
    transport
        .sent()
        .iter()
        .map(|(path, body)| {
            assert_eq!(path, INVENTORY_PATH);
            body["report_id"].as_str().unwrap().to_owned()
        })
        .collect()
}

#[test]
fn the_startup_report_is_sent_at_once_conforms_and_is_recorded() {
    let h = Harness::new();
    let mut reporter = h.reporter();
    let transport = FakeTransport::new(vec![]);
    let now = h.at(Duration::ZERO);
    let (_, logs) = logs_of(|| {
        // The reply must echo the id, which is only known once built, so answer on the fly.
        let mut collect = || h.facts.borrow().clone();
        transport.push_with(accepted);
        reporter.tick(now, &mut collect, &transport)
    });
    let sent = transport.sent();
    assert_eq!(sent.len(), 1);
    let (path, body) = &sent[0];
    assert_eq!(path, INVENTORY_PATH);
    assert_conforms("v1", "inventory.request", body);
    assert_eq!(body["schema_version"], 1);
    assert_eq!(body["agent_version"], AGENT_VERSION);
    assert_eq!(body["hostname"], "vm-01.example.lan");
    assert!(
        logs.contains("sending the startup inventory report"),
        "{logs}"
    );
    assert!(logs.contains("stable_changed=true rebooted=true"), "{logs}");
    assert!(logs.contains("inventory report sent"), "{logs}");
    assert!(logs.contains(&format!(
        "report_id=\"{}\"",
        body["report_id"].as_str().unwrap()
    )));
    assert!(logs.contains("reason=\"startup\""), "{logs}");

    let record = h.record().expect("record saved");
    assert_eq!(record.report_id, body["report_id"].as_str().unwrap());
    assert_eq!(record.stable_hash, StableHash::of(&sample()).to_string());
    assert_eq!(record.boot_id.as_deref(), sample().boot_id.as_deref());
    assert_eq!(record.agent_version, AGENT_VERSION);
}

#[test]
fn a_degraded_collection_is_still_a_conforming_report() {
    let h = Harness::new();
    {
        let mut facts = h.facts.borrow_mut();
        facts.hostname = None;
        facts.disks = None;
        facts.warnings = vec![crate::collect::Warning {
            field: crate::collect::Field::Hostname,
            message: "/proc/sys/kernel/hostname: read timed out after 5s".into(),
        }];
    }
    let mut reporter = h.reporter();
    let transport = FakeTransport::new(vec![]);
    let (_, _) = logs_of(|| h.tick(&mut reporter, &transport, h.at(Duration::ZERO)));
    let body = &transport.sent()[0].1;
    assert_conforms("v1", "inventory.request", body);
    assert_eq!(body["hostname"], serde_json::Value::Null);
    assert_eq!(body["warnings"][0]["field"], "hostname");
}

#[test]
fn a_retried_send_reuses_the_report_id_and_body() {
    let h = Harness::new();
    let mut reporter = h.reporter();
    let transport = FakeTransport::new(vec![
        Err(ApiError::Transport("connection refused".into())),
        Err(ApiError::Server {
            status: 503,
            request_id: None,
        }),
    ]);
    let (_, logs) = logs_of(|| {
        let mut now = h.at(Duration::ZERO);
        now = h.tick(&mut reporter, &transport, now);
        now = h.tick(&mut reporter, &transport, now);
        transport.push_with(accepted);
        h.tick(&mut reporter, &transport, now);
    });
    let sent = transport.sent();
    assert_eq!(sent.len(), 3);
    assert!(
        sent.iter().all(|(_, body)| *body == sent[0].1),
        "a retry changed the body"
    );
    assert_eq!(h.collections.get(), 1, "a retry collected again");
    assert!(
        logs.contains("cannot reach the fleet server; will retry"),
        "{logs}"
    );
    // Failure lines carry the report id through the span.
    let id = sent[0].1["report_id"].as_str().unwrap();
    assert_eq!(
        logs.matches(&format!("report_id=\"{id}\"")).count(),
        4,
        "{logs}"
    );
    assert!(logs.contains("attempt=3"), "{logs}");
    assert_eq!(reporter.pending_report_id(), None);
}

#[test]
fn a_new_report_gets_a_new_id_on_schedule() {
    let h = Harness::new();
    let mut reporter = h.reporter();
    let transport = FakeTransport::new(vec![]);
    let (_, logs) = logs_of(|| {
        h.drive(
            &mut reporter,
            &transport,
            h.at(Duration::ZERO),
            secs(3 * 900),
            true,
        )
    });
    let ids = ids(&transport);
    // Startup, then one every 810..=900 s: three or four reports in 2700 s.
    assert!((3..=4).contains(&ids.len()), "{ids:?}");
    assert_eq!(
        ids.iter().collect::<HashSet<_>>().len(),
        ids.len(),
        "an id was reused"
    );
    assert_eq!(
        logs.matches("reason=\"scheduled\"").count(),
        ids.len() - 1,
        "{logs}"
    );
    // Unchanged facts were checked every minute without sending anything extra.
    assert!(h.collections.get() >= 40, "{}", h.collections.get());
}

#[test]
fn a_stable_change_triggers_a_report_within_the_check_interval() {
    let h = Harness::new();
    let mut reporter = h.reporter();
    let transport = FakeTransport::new(vec![]);
    let mut now = h.drive(
        &mut reporter,
        &transport,
        h.at(Duration::ZERO),
        secs(100),
        true,
    );
    assert_eq!(transport.sent().len(), 1);

    // An address is added.
    h.facts.borrow_mut().network_interfaces.as_mut().unwrap()[0]
        .addresses
        .push("2001:db8::10/64".into());
    let changed_at = now;
    let (_, logs) = logs_of(|| {
        now = h.drive(
            &mut reporter,
            &transport,
            now,
            secs(100) + CHANGE_CHECK_INTERVAL,
            true,
        );
    });
    let sent = transport.sent();
    assert_eq!(sent.len(), 2, "no report for a stable change");
    assert!(now <= changed_at + CHANGE_CHECK_INTERVAL + secs(1));
    assert_eq!(
        sent[1].1["network_interfaces"][0]["addresses"][1],
        "2001:db8::10/64"
    );
    assert_ne!(sent[0].1["report_id"], sent[1].1["report_id"]);
    assert!(
        logs.contains("stable facts changed; sending an inventory report"),
        "{logs}"
    );
    assert!(logs.contains("reason=\"stable_change\""), "{logs}");
    // The record follows the new facts.
    assert_eq!(
        h.record().unwrap().stable_hash,
        StableHash::of(&h.facts.borrow()).to_string()
    );
    // And it is reported once, not on every check.
    h.drive(&mut reporter, &transport, now, secs(700), true);
    assert_eq!(transport.sent().len(), 2);
}

#[test]
fn every_stable_field_counts_and_no_volatile_one_does() {
    let base = StableHash::of(&sample());
    type Change = (&'static str, fn(&mut Inventory));
    let stable: Vec<Change> = vec![
        ("hostname", |i| {
            i.hostname = Some("vm-02.example.lan".into())
        }),
        ("os", |i| {
            i.os.as_mut().unwrap().version_id = Some("14".into())
        }),
        ("kernel", |i| {
            i.kernel_version = Some("6.12.40+deb13-amd64".into())
        }),
        ("architecture", |i| i.architecture = None),
        ("cpu model", |i| i.cpu_model = Some("other".into())),
        ("cpu cores", |i| i.cpu_cores = Some(4)),
        ("memory total", |i| {
            i.memory_total_bytes = Some(8_000_000_000)
        }),
        ("boot id", |i| {
            i.boot_id = Some("00000000-0000-4000-8000-000000000003".into())
        }),
        ("machine id", |i| i.machine_id = None),
        ("disk size", |i| {
            i.disks.as_mut().unwrap()[0].size_bytes += 1
        }),
        ("disk added", |i| {
            i.disks.as_mut().unwrap().push(Disk {
                mount: "/srv".into(),
                filesystem: "ext4".into(),
                size_bytes: 1,
                free_bytes: 1,
            })
        }),
        ("primary", |i| {
            i.network_interfaces.as_mut().unwrap()[0].primary = false
        }),
    ];
    for (name, change) in stable {
        let mut inventory = sample();
        change(&mut inventory);
        assert_ne!(StableHash::of(&inventory), base, "{name}");
    }
    let mut volatile = sample();
    volatile.memory_available_bytes = Some(1);
    volatile.uptime_seconds = Some(999_999);
    volatile.disks.as_mut().unwrap()[0].free_bytes = 1;
    assert_eq!(StableHash::of(&volatile), base);
    // The hash is a stable function of the facts, not of the process (it is persisted).
    assert_eq!(StableHash::of(&sample()), base);
    assert_eq!(StableHash::parse(&base.to_string()), Some(base));
    for bad in [
        "",
        "fnv1a128:",
        "fnv1a128:xyz",
        "sha256:00",
        "fnv1a128:0123",
    ] {
        assert_eq!(StableHash::parse(bad), None, "{bad}");
    }
}

#[test]
fn a_volatile_only_change_triggers_no_extra_report() {
    let h = Harness::new();
    let mut reporter = h.reporter();
    let transport = FakeTransport::new(vec![]);
    let mut now = h.drive(
        &mut reporter,
        &transport,
        h.at(Duration::ZERO),
        secs(30),
        true,
    );
    assert_eq!(transport.sent().len(), 1);
    for step in 1..=12u64 {
        {
            let mut facts = h.facts.borrow_mut();
            facts.memory_available_bytes = Some(3_000_000_000 - step * 1_000_000);
            facts.uptime_seconds = Some(3600 + step * 60);
            facts.disks.as_mut().unwrap()[0].free_bytes -= step;
        }
        now = h.drive(&mut reporter, &transport, now, secs(30 + step * 60), true);
    }
    // 12 minutes of volatile changes, under one inventory interval: still only the startup report.
    assert_eq!(transport.sent().len(), 1);
    assert!(h.collections.get() >= 12);
}

#[test]
fn a_rejected_report_is_logged_not_retried_and_the_agent_keeps_going() {
    let h = Harness::new();
    let mut reporter = h.reporter();
    let transport = FakeTransport::new(vec![Err(ApiError::Rejected {
        status: 400,
        code: "validation_failed".into(),
        message: "/disks/0/free_bytes: exceeds size_bytes".into(),
        request_id: Some("req-400".into()),
    })]);
    let (now, logs) = logs_of(|| {
        let now = h.tick(&mut reporter, &transport, h.at(Duration::ZERO));
        // Checks keep running without resending the same facts.
        h.drive(&mut reporter, &transport, now, secs(600), true)
    });
    let sent = transport.sent();
    assert_eq!(sent.len(), 1, "a rejected report was retried");
    let id = sent[0].1["report_id"].as_str().unwrap();
    let line = logs
        .lines()
        .find(|l| l.contains("rejected the inventory report"))
        .unwrap_or_else(|| panic!("{logs}"));
    assert!(line.contains("ERROR"), "{line}");
    assert!(line.contains(&format!("report_id=\"{id}\"")), "{line}");
    assert!(line.contains("code=\"validation_failed\""), "{line}");
    assert!(
        line.contains("server_message=\"/disks/0/free_bytes: exceeds size_bytes\""),
        "{line}"
    );
    assert!(line.contains("request_id=\"req-400\""), "{line}");
    assert!(line.contains("status=400"), "{line}");
    // Nothing was recorded as reported.
    assert_eq!(h.record(), None);
    // The next report follows the normal schedule, with a new id.
    h.drive(&mut reporter, &transport, now, secs(1000), true);
    let ids = ids(&transport);
    assert_eq!(ids.len(), 2, "{ids:?}");
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn an_oversized_report_is_not_retried_either() {
    let h = Harness::new();
    let mut reporter = h.reporter();
    let transport = FakeTransport::new(vec![Err(ApiError::PayloadTooLarge { request_id: None })]);
    let (_, logs) = logs_of(|| {
        let now = h.tick(&mut reporter, &transport, h.at(Duration::ZERO));
        h.drive(&mut reporter, &transport, now, secs(600), true)
    });
    assert_eq!(transport.sent().len(), 1);
    assert!(logs.contains("code=\"payload_too_large\""), "{logs}");
}

#[test]
fn an_outage_replays_nothing_and_current_state_is_sent_on_recovery() {
    let h = Harness::new();
    let mut reporter = h.reporter();
    let transport = FakeTransport::new(vec![]);
    let (_, logs) = logs_of(|| {
        // The server is down for 40 minutes; the facts change twice meanwhile.
        let mut now = h.drive(
            &mut reporter,
            &transport,
            h.at(Duration::ZERO),
            secs(600),
            false,
        );
        h.facts.borrow_mut().kernel_version = Some("6.12.40+deb13-amd64".into());
        now = h.drive(&mut reporter, &transport, now, secs(1200), false);
        h.facts.borrow_mut().cpu_cores = Some(4);
        now = h.drive(&mut reporter, &transport, now, secs(2400), false);
        let before = transport.sent().len();
        // The server returns.
        h.drive(&mut reporter, &transport, now, secs(2400 + 400), true);
        before
    });
    let sent = transport.sent();
    // While down: retries, never more than one attempt per backoff step, and no id ever reappears
    // after a newer one was built.
    let ids = ids(&transport);
    let mut seen = Vec::<&String>::new();
    for id in &ids {
        if seen.last() != Some(&id) {
            assert!(!seen.contains(&id), "report {id} was replayed");
            seen.push(id);
        }
    }
    assert!(seen.len() >= 3, "{seen:?}");
    assert!(
        logs.contains("replacing an unsent inventory report with current state"),
        "{logs}"
    );
    // The first accepted report carries current state, and only one report is accepted.
    let accepted_body = &sent[sent.len() - 1].1;
    assert_eq!(accepted_body["kernel_version"], "6.12.40+deb13-amd64");
    assert_eq!(accepted_body["cpu_cores"], 4);
    assert_eq!(logs.matches("inventory report sent").count(), 1, "{logs}");
    assert_eq!(
        h.record().unwrap().report_id,
        accepted_body["report_id"].as_str().unwrap()
    );
}

#[test]
fn a_long_backoff_is_honoured_even_when_a_change_is_detected() {
    let h = Harness::new();
    let mut reporter = h.reporter();
    let transport = FakeTransport::new(vec![Err(ApiError::Unauthorized { request_id: None })]);
    let (_, _) = logs_of(|| {
        let now = h.tick(&mut reporter, &transport, h.at(Duration::ZERO));
        h.facts.borrow_mut().hostname = Some("vm-02.example.lan".into());
        // 25 minutes: under the 27..=30 minute wait after a 401.
        h.drive(&mut reporter, &transport, now, secs(25 * 60), false);
    });
    assert_eq!(
        transport.sent().len(),
        1,
        "the backoff after a 401 was not honoured"
    );
}

#[test]
fn a_restart_with_unchanged_facts_sends_only_the_startup_report() {
    let h = Harness::new();
    {
        let mut reporter = h.reporter();
        let transport = FakeTransport::new(vec![]);
        h.drive(
            &mut reporter,
            &transport,
            h.at(Duration::ZERO),
            secs(30),
            true,
        );
    }
    let first = h.record().unwrap();
    // Restart: same boot, same facts.
    let mut reporter = h.reporter();
    let transport = FakeTransport::new(vec![]);
    let (_, logs) = logs_of(|| h.drive(&mut reporter, &transport, h.at(secs(40)), secs(800), true));
    assert_eq!(transport.sent().len(), 1, "{logs}");
    assert!(
        logs.contains("stable_changed=false rebooted=false"),
        "{logs}"
    );
    assert!(
        logs.contains(&format!("last_report_id=\"{}\"", first.report_id)),
        "{logs}"
    );
    assert_ne!(h.record().unwrap().report_id, first.report_id);
}

#[test]
fn a_restart_after_a_reboot_or_change_says_so() {
    let h = Harness::new();
    {
        let mut reporter = h.reporter();
        let transport = FakeTransport::new(vec![]);
        h.drive(
            &mut reporter,
            &transport,
            h.at(Duration::ZERO),
            secs(30),
            true,
        );
    }
    h.facts.borrow_mut().boot_id = Some("00000000-0000-4000-8000-000000000009".into());
    let mut reporter = h.reporter();
    let transport = FakeTransport::new(vec![]);
    let (_, logs) = logs_of(|| h.drive(&mut reporter, &transport, h.at(secs(40)), secs(100), true));
    assert!(logs.contains("stable_changed=true rebooted=true"), "{logs}");
    assert_eq!(
        h.record().unwrap().boot_id.as_deref(),
        Some("00000000-0000-4000-8000-000000000009")
    );
}

#[test]
fn a_missing_or_corrupt_record_is_treated_as_none() {
    for contents in [
        &b"not json"[..],
        b"{\"stable_hash\":\"md5:00\",\"boot_id\":null,\"agent_version\":\"0.1.0\",\"report_id\":\"x\",\"reported_at\":\"x\"}",
        b"",
    ] {
        let h = Harness::new();
        fs::write(h.state_dir().join(RECORD_NAME), contents).unwrap();
        let (mut reporter, logs) = logs_of(|| h.reporter());
        assert!(logs.contains("the inventory state is corrupt; starting without it"), "{logs}");
        let transport = FakeTransport::new(vec![]);
        let (_, logs) = logs_of(|| h.drive(&mut reporter, &transport, h.at(Duration::ZERO), secs(30), true));
        assert!(logs.contains("stable_changed=true"), "{logs}");
        assert_eq!(transport.sent().len(), 1);
        // A good record replaces it.
        assert!(h.record().is_some());
    }
    // A record that is a symlink is not followed.
    let h = Harness::new();
    let target = h.dir.write("elsewhere.json", "{}");
    std::os::unix::fs::symlink(&target, h.state_dir().join(RECORD_NAME)).unwrap();
    let (_, logs) = logs_of(|| h.reporter());
    assert!(logs.contains("cannot read the inventory state"), "{logs}");
}

#[test]
fn an_unwritable_state_directory_is_logged_and_reporting_continues() {
    let h = Harness::new();
    let mut reporter = h.reporter();
    fs::remove_dir_all(h.state_dir()).unwrap();
    let transport = FakeTransport::new(vec![]);
    let (_, logs) = logs_of(|| {
        h.drive(
            &mut reporter,
            &transport,
            h.at(Duration::ZERO),
            secs(1000),
            true,
        )
    });
    assert!(logs.contains("cannot save the inventory state"), "{logs}");
    assert_eq!(transport.sent().len(), 2);
}

#[test]
fn a_duplicate_reply_is_logged_as_such() {
    let h = Harness::new();
    let mut reporter = h.reporter();
    let transport = FakeTransport::new(vec![]);
    transport.push_with(|body| ok(json!({"report_id": body["report_id"], "duplicate": true})));
    let (_, logs) = logs_of(|| h.tick(&mut reporter, &transport, h.at(Duration::ZERO)));
    assert!(logs.contains("inventory report was a duplicate"), "{logs}");
    assert!(h.record().is_some());
    // A reply naming another report is still an acceptance, with a warning.
    let h = Harness::new();
    let mut reporter = h.reporter();
    let transport = FakeTransport::new(vec![ok(
        json!({"report_id": "00000000-0000-4000-8000-000000000001", "duplicate": false}),
    )]);
    let (_, logs) = logs_of(|| h.tick(&mut reporter, &transport, h.at(Duration::ZERO)));
    assert!(logs.contains("does not name this report"), "{logs}");
    assert_eq!(reporter.pending_report_id(), None);
}

#[test]
fn the_server_directed_inventory_interval_is_followed() {
    let h = Harness::new();
    let mut reporter = h.reporter();
    h.intervals.apply(crate::report::envelope::ServerIntervals {
        heartbeat_seconds: None,
        inventory_seconds: Some(300),
    });
    let transport = FakeTransport::new(vec![]);
    let (_, _) = logs_of(|| {
        h.drive(
            &mut reporter,
            &transport,
            h.at(Duration::ZERO),
            secs(1500),
            true,
        )
    });
    // Startup then every 270..=300 s: five or six reports in 1500 s, instead of two at 900 s.
    let count = transport.sent().len();
    assert!((5..=6).contains(&count), "{count}");
}

#[test]
fn a_report_that_cannot_be_built_is_postponed_without_a_tight_loop() {
    let h = Harness::new();
    let mut reporter = h.reporter();
    reporter.new_id = || Err(std::io::Error::other("no randomness"));
    let transport = FakeTransport::new(vec![]);
    let (wake, logs) = logs_of(|| h.tick(&mut reporter, &transport, h.at(Duration::ZERO)));
    assert!(wake >= h.at(CHANGE_CHECK_INTERVAL), "retried too soon");
    assert!(logs.contains("cannot generate a report id"), "{logs}");
    assert!(transport.sent().is_empty());
    // Once ids work again, the startup report goes out.
    reporter.new_id = new_report_id;
    let (_, logs) = logs_of(|| h.tick(&mut reporter, &transport, wake));
    assert_eq!(transport.sent().len(), 1);
    assert!(
        logs.contains("sending the startup inventory report"),
        "{logs}"
    );
}

#[test]
fn a_report_waiting_for_its_retry_is_replaced_once_an_interval_old() {
    // Only volatile facts change, so nothing but the report's age can replace it.
    let h = Harness::new();
    let mut reporter = h.reporter();
    let transport = FakeTransport::new(vec![]);
    let (_, logs) = logs_of(|| {
        let mut now = h.drive(
            &mut reporter,
            &transport,
            h.at(Duration::ZERO),
            secs(60),
            false,
        );
        h.facts.borrow_mut().uptime_seconds = Some(99_999);
        now = h.drive(&mut reporter, &transport, now, secs(1000), false);
        h.drive(&mut reporter, &transport, now, secs(1400), true);
    });
    let ids = ids(&transport);
    let first = ids[0].clone();
    let last = ids.last().unwrap().clone();
    assert_ne!(
        first, last,
        "a report older than the interval was still being retried"
    );
    assert!(
        logs.contains("replacing an unsent inventory report"),
        "{logs}"
    );
    // The startup report was retried with its id until replaced, never after.
    let replaced_at = ids.iter().position(|id| *id != first).unwrap();
    assert!(
        replaced_at >= 2 && ids[replaced_at..].iter().all(|id| *id != first),
        "{ids:?}"
    );
    assert_eq!(transport.sent().last().unwrap().1["uptime_seconds"], 99_999);
}
