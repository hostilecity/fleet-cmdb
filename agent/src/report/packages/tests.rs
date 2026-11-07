//! Package reporter tests with a scripted transport, simulated time, and the fake host
//! (P2-AGENT-PACKAGES, FR-2.3): contract, compression, scheduling, retry with the same id, requests,
//! stopping, size limits, and memory.

use std::io::Read;
use std::path::Path;

use serde_json::json;

use super::*;
use crate::client::ApiResponse;
use crate::collect::contract::assert_conforms;
use crate::facts::fake::{FakeHost, package_fixture};
use crate::facts::host::{Command, RunError, Stat};
use crate::packages::tests::{SyntheticDpkg, synthetic_output};
use crate::packages::{DPKG_STATUS, MAX_PACKAGES};
use crate::report::tests::FakeTransport;
use crate::retry::{RetryPolicy, SplitMix64};
use crate::test_support::memory;

const INTERVAL: Duration = Duration::from_secs(6 * 3600);

fn reporter(host: &dyn Host) -> Reporter<'_, SplitMix64> {
    Reporter::new(
        host,
        INTERVAL,
        Backoff::new(RetryPolicy::default(), SplitMix64::new(1)),
        SplitMix64::new(2),
    )
}

fn transport() -> FakeTransport {
    let transport = FakeTransport::new(vec![]);
    transport.set_accepting(true);
    transport
}

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

/// The package reports posted so far, as the server reads them.
fn posts(transport: &FakeTransport) -> Vec<Value> {
    transport
        .sent()
        .into_iter()
        .filter(|(path, _)| path == PACKAGES_PATH)
        .map(|(_, body)| body)
        .collect()
}

fn down() -> Result<ApiResponse, ApiError> {
    Err(ApiError::Transport("connection refused".into()))
}

fn gunzip(body: &[u8]) -> Value {
    let mut json = Vec::new();
    flate2::read::GzDecoder::new(body)
        .read_to_end(&mut json)
        .unwrap();
    serde_json::from_slice(&json).unwrap()
}

#[test]
fn the_startup_report_is_gzip_and_conforms_to_the_contract_with_every_package() {
    let host = FakeHost::debian13();
    let transport = transport();
    let mut reporter = reporter(&host);
    reporter.tick(Instant::now(), &transport);

    let sent = posts(&transport);
    assert_eq!(sent.len(), 1);
    assert_eq!(transport.gzipped(), [PACKAGES_PATH], "sent compressed");
    let body = &sent[0];
    assert_conforms("v1", "packages.request", body);
    assert_eq!(body["manager"], "dpkg");
    assert_eq!(body["unsupported_reason"], Value::Null);
    assert_eq!(body["warnings"], json!([]));
    // The interrupted installations of the fixture are named, with their state, and are not packages.
    assert_eq!(
        body["skipped"],
        json!([
            {"name": "man-db", "reason": "half-configured"},
            {"name": "qemu-guest-agent", "reason": "unpacked"},
            {"name": "systemd", "reason": "triggers-pending"},
        ])
    );
    assert_eq!(body["agent_version"], AGENT_VERSION);
    // Every package of the listing, as parsed.
    let listed = packages::parse(&package_fixture("dpkg-query-show")).packages;
    assert_eq!(body["packages"], serde_json::to_value(&listed).unwrap());
    let bsdutils = body["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "bsdutils")
        .unwrap();
    assert_eq!(
        bsdutils,
        &json!({"name": "bsdutils", "version": "1:2.41-5", "architecture": "amd64", "source": "util-linux"})
    );
}

#[test]
fn an_unsupported_host_says_so_and_why_with_no_packages() {
    let host = FakeHost::default().with_stat("/usr/bin/rpm", 0o755, 0, 0);
    let transport = transport();
    reporter(&host).tick(Instant::now(), &transport);
    let body = &posts(&transport)[0];
    assert_conforms("v1", "packages.request", body);
    assert_eq!(body["manager"], "unsupported");
    assert_eq!(body["packages"], json!([]));
    assert_eq!(
        body["unsupported_reason"],
        "no dpkg database at /var/lib/dpkg/status; rpm was found, which is not supported (only dpkg is, DEC-01)"
    );
}

#[test]
fn a_host_with_nothing_skipped_sends_no_skipped_array() {
    // Absent means none: the body is what a server that predates `skipped` already takes.
    let output = b"installed\tfine\tall\t1\tfine\n".to_vec();
    let host = FakeHost::debian13().with_output("dpkg-query --show", Ok(output));
    let transport = transport();
    reporter(&host).tick(Instant::now(), &transport);
    let body = &posts(&transport)[0];
    assert_conforms("v1", "packages.request", body);
    assert_eq!(body["manager"], "dpkg");
    assert!(body.get("skipped").is_none(), "{body}");
}

#[test]
fn lines_with_a_readable_name_are_skipped_and_named_in_the_report() {
    let mut output = package_fixture("dpkg-query-show");
    output.extend_from_slice(b"installed\tbadver\tamd64\t1 2\tbadver\n");
    output.extend_from_slice(b"installed\tOdd\tamd64\t1.0\todd\n");
    let host = FakeHost::debian13().with_output("dpkg-query --show", Ok(output));
    let transport = transport();
    reporter(&host).tick(Instant::now(), &transport);
    let body = &posts(&transport)[0];
    assert_conforms("v1", "packages.request", body);
    let skipped = body["skipped"].as_array().unwrap();
    assert!(
        skipped.contains(
            &json!({"name": "badver", "reason": "version is not one a package report can carry"})
        ),
        "{skipped:?}"
    );
    // `Odd` has no readable name: a warning only.
    assert!(!skipped.iter().any(|s| s["name"] == "Odd"));
    assert_eq!(body["warnings"].as_array().unwrap().len(), 2);
}

#[test]
fn more_skipped_than_the_contract_allows_are_counted_in_a_warning() {
    let output: String = (0..100)
        .map(|i| format!("unpacked\tstuck-{i:03}\tamd64\t1.0\tstuck\n"))
        .collect();
    let host = FakeHost::debian13().with_output("dpkg-query --show", Ok(output.into_bytes()));
    let transport = transport();
    reporter(&host).tick(Instant::now(), &transport);
    let body = &posts(&transport)[0];
    assert_conforms("v1", "packages.request", body);
    assert_eq!(body["manager"], "dpkg");
    assert_eq!(body["skipped"].as_array().unwrap().len(), 64);
    assert_eq!(
        body["warnings"],
        json!([{"field": "packages", "message": "36 more packages were skipped; their names are not listed (at most 64 are)"}])
    );
}

#[test]
fn a_dpkg_that_cannot_be_listed_is_reported_unreadable_with_the_reason() {
    let cases = [
        (
            FakeHost::debian13().with_output(
                "dpkg-query --show",
                Err(RunError::Failed {
                    status: "exit status 2".into(),
                    stderr: "dpkg-query: error: parsing file".into(),
                }),
            ),
            "dpkg-query --show failed (exit status 2): dpkg-query: error: parsing file",
        ),
        (
            FakeHost::debian13().with_output(
                "dpkg-query --show",
                Err(RunError::TimedOut(crate::packages::TIMEOUT)),
            ),
            "dpkg-query --show did not finish within 20 seconds",
        ),
        (
            FakeHost::debian13().denying(DPKG_STATUS),
            "permission denied reading /var/lib/dpkg/status",
        ),
    ];
    for (host, reason) in cases {
        let transport = transport();
        reporter(&host).tick(Instant::now(), &transport);
        let body = &posts(&transport)[0];
        assert_conforms("v1", "packages.request", body);
        assert_eq!(body["manager"], "unreadable");
        assert_eq!(body["unsupported_reason"], reason);
        assert_eq!(body["packages"], json!([]));
        assert!(body.get("skipped").is_none(), "{body}");
    }
}

#[test]
fn warnings_reach_the_report() {
    let mut output = package_fixture("dpkg-query-show");
    output.extend_from_slice(b"installed\tOdd\tamd64\t1.0\todd\n");
    let host = FakeHost::debian13().with_output("dpkg-query --show", Ok(output));
    let transport = transport();
    reporter(&host).tick(Instant::now(), &transport);
    let body = &posts(&transport)[0];
    assert_conforms("v1", "packages.request", body);
    assert_eq!(body["packages"].as_array().unwrap().len(), 28);
    assert_eq!(
        body["warnings"],
        json!([{"field": "packages", "message": "package name `Odd` is not one a package report can carry; skipped"}])
    );
}

#[test]
fn reports_follow_the_config_interval_less_jitter() {
    let host = FakeHost::debian13();
    let transport = transport();
    let mut reporter = reporter(&host);
    let t0 = Instant::now();
    let wake = reporter.tick(t0, &transport);
    assert!(wake <= t0 + INTERVAL && wake >= t0 + INTERVAL - INTERVAL / 10);
    // Nothing more until then.
    reporter.tick(wake - secs(1), &transport);
    assert_eq!(posts(&transport).len(), 1);
    reporter.tick(wake, &transport);
    let sent = posts(&transport);
    assert_eq!(sent.len(), 2);
    assert_ne!(sent[0]["report_id"], sent[1]["report_id"]);
}

#[test]
fn a_failed_send_is_retried_with_the_same_report_id_and_body() {
    let host = FakeHost::debian13();
    let transport = FakeTransport::new(vec![down(), down()]);
    transport.set_accepting(true);
    let mut reporter = reporter(&host);
    let t0 = Instant::now();
    let mut now = t0;
    for _ in 0..3 {
        now = reporter.tick(now, &transport);
    }
    let sent = posts(&transport);
    assert_eq!(sent.len(), 3);
    assert!(sent.iter().all(|b| b == &sent[0]), "same id and body");
    assert!(reporter.pending_report_id().is_none(), "accepted at last");
    // Listed once: a retry sends what was listed, it does not list again.
    let runs = host.log().iter().filter(|l| l.starts_with("run ")).count();
    assert_eq!(runs, 1);
}

#[test]
fn the_backoff_starts_when_the_failed_request_ends() {
    // Review of #117: the retry time was `now` (before the listing and the request) plus the backoff,
    // so a request that took its 30 s timeout had used up a 2.5 to 5 s backoff and was retried at once.
    let slow = Duration::from_millis(300);
    let wake_after = |delay: Duration| {
        let host = FakeHost::debian13();
        let transport = FakeTransport::new(vec![]);
        transport.push_with(move |_| {
            std::thread::sleep(delay);
            down()
        });
        let t0 = Instant::now();
        let wake = reporter(&host).tick(t0, &transport);
        wake - t0
    };
    let fast = wake_after(Duration::ZERO);
    let late = wake_after(slow);
    assert!(fast < INTERVAL, "a retry is due: {fast:?}");
    // Same seed, same backoff: the slow failure's retry is later by the time the request took (less
    // a margin for the few real milliseconds of the rest of the tick).
    assert!(
        late >= fast + slow - Duration::from_millis(50),
        "fast {fast:?}, slow {late:?}"
    );
}

#[test]
fn a_request_replaces_a_report_waiting_for_its_retry() {
    let host = FakeHost::debian13();
    let transport = FakeTransport::new(vec![down()]);
    transport.set_accepting(true);
    let mut reporter = reporter(&host);
    let t0 = Instant::now();
    reporter.tick(t0, &transport);
    let waiting = reporter.pending_report_id().unwrap().to_owned();
    reporter.request();
    reporter.tick(t0 + secs(1), &transport);
    let sent = posts(&transport);
    assert_eq!(sent.len(), 2);
    assert_ne!(sent[1]["report_id"], json!(waiting));
    assert!(reporter.pending_report_id().is_none());
}

#[test]
fn one_request_gives_exactly_one_extra_report_and_answers_it() {
    let host = FakeHost::debian13();
    let transport = transport();
    let mut reporter = reporter(&host);
    let t0 = Instant::now();
    reporter.tick(t0, &transport);
    assert!(
        !reporter.take_answered(),
        "a startup report answers nothing"
    );
    reporter.request();
    reporter.tick(t0 + secs(10), &transport);
    assert!(reporter.take_answered());
    assert!(!reporter.take_answered(), "once");
    for i in 1..20 {
        reporter.tick(t0 + secs(10 + i * 5), &transport);
    }
    assert_eq!(posts(&transport).len(), 2);
}

#[test]
fn a_requested_report_the_server_rejects_answers_nothing_and_is_not_retried() {
    let host = FakeHost::debian13();
    let transport = transport();
    let mut reporter = reporter(&host);
    let t0 = Instant::now();
    reporter.tick(t0, &transport);
    for error in [
        ApiError::Rejected {
            status: 422,
            code: "validation_failed".into(),
            message: "no".into(),
            request_id: None,
        },
        ApiError::PayloadTooLarge { request_id: None },
    ] {
        transport.push(Err(error));
        reporter.request();
        reporter.tick(t0 + secs(5), &transport);
        assert!(!reporter.take_answered());
        assert!(reporter.pending_report_id().is_none(), "not kept to retry");
    }
    assert_eq!(posts(&transport).len(), 3);
}

/// A host whose `dpkg-query` takes the stop request with it: SIGTERM while the listing runs.
struct StopDuringListing<'a> {
    inner: FakeHost,
    stop: &'a crate::shutdown::Shutdown,
}

impl Host for StopDuringListing<'_> {
    fn stat(&self, path: &Path) -> io::Result<Stat> {
        self.inner.stat(path)
    }
    fn read(&self, path: &Path, max: u64) -> io::Result<Vec<u8>> {
        self.inner.read(path, max)
    }
    fn list(&self, dir: &Path, max: usize) -> io::Result<Vec<String>> {
        self.inner.list(dir, max)
    }
    fn run(&self, command: &Command) -> Result<Vec<u8>, RunError> {
        let output = self.inner.run(command);
        self.stop.request();
        output
    }
}

#[test]
fn a_stop_during_the_listing_drops_it_and_sends_nothing() {
    let stop = crate::shutdown::Shutdown::default();
    let host = StopDuringListing {
        inner: FakeHost::debian13(),
        stop: &stop,
    };
    let transport = transport();
    let mut reporter = reporter(&host).stopping_on(&stop);
    let t0 = Instant::now();
    reporter.tick(t0, &transport);
    assert!(posts(&transport).is_empty(), "sent while stopping");
    assert!(reporter.pending_report_id().is_none(), "kept to send");
    reporter.request();
    reporter.tick(t0 + INTERVAL * 2, &transport);
    assert!(posts(&transport).is_empty());
    assert_eq!(
        host.inner
            .log()
            .iter()
            .filter(|l| l.starts_with("run "))
            .count(),
        1,
        "nothing started after the stop"
    );
}

#[test]
fn a_stop_before_the_tick_runs_nothing() {
    let stop = crate::shutdown::Shutdown::default();
    stop.request();
    let host = FakeHost::debian13();
    let transport = transport();
    reporter(&host)
        .stopping_on(&stop)
        .tick(Instant::now(), &transport);
    assert!(host.log().is_empty(), "{:?}", host.log());
    assert!(transport.sent().is_empty());
}

#[test]
fn a_report_waiting_for_its_retry_is_not_sent_once_stopping() {
    let stop = crate::shutdown::Shutdown::default();
    let host = FakeHost::debian13();
    let transport = FakeTransport::new(vec![down()]);
    transport.set_accepting(true);
    let mut reporter = reporter(&host).stopping_on(&stop);
    let t0 = Instant::now();
    let retry = reporter.tick(t0, &transport);
    stop.request();
    reporter.tick(retry, &transport);
    assert_eq!(posts(&transport).len(), 1, "only the first attempt");
}

/// A listing of `count` packages with versions of 200 pseudo-random printable characters, which
/// compress poorly.
fn incompressible(count: usize) -> Listing {
    let mut rng = SplitMix64::new(9);
    let packages = (0..count)
        .map(|i| {
            let version: String = (0..200)
                .map(|_| char::from(b'0' + (rng.next_u64() % 75) as u8))
                .filter(|c| *c != '\\')
                .collect();
            Package {
                name: format!("package-{i:05}"),
                version,
                architecture: "amd64".into(),
                source: Some(format!("source-{i:05}")),
            }
        })
        .collect();
    Listing {
        packages,
        ..Listing::default()
    }
}

#[test]
fn a_listing_over_the_json_limit_is_reported_unreadable_not_cut() {
    let listing = incompressible(MAX_PACKAGES);
    let encoded = encode(
        "00000000-0000-4000-8000-000000000001",
        "2026-01-01T12:00:00Z",
        &Collected::Dpkg(listing),
    );
    let refused = encoded.refused.clone().expect("refused");
    assert!(
        refused.contains("more than the 4000000 bytes of JSON"),
        "{refused}"
    );
    let body = gunzip(&encoded.body);
    assert_conforms("v1", "packages.request", &body);
    assert_eq!(body["manager"], "unreadable");
    assert_eq!(body["unsupported_reason"], json!(refused));
    assert_eq!(body["packages"], json!([]));
}

#[test]
fn a_listing_over_the_compressed_limit_is_reported_unreadable_not_cut() {
    // About 3.3 MB of JSON, within the JSON limit, that compresses to well over 1 MB.
    let listing = incompressible(13_000);
    let encoded = encode(
        "00000000-0000-4000-8000-000000000001",
        "2026-01-01T12:00:00Z",
        &Collected::Dpkg(listing),
    );
    let refused = encoded.refused.clone().expect("refused");
    assert!(
        refused.contains("compresses to") && refused.contains("more than the 1000000"),
        "{refused}"
    );
    let body = gunzip(&encoded.body);
    assert_conforms("v1", "packages.request", &body);
    assert_eq!(body["manager"], "unreadable");
}

#[test]
fn the_most_packages_of_a_realistic_host_fit_the_limits() {
    // 20,000 packages of realistic size (the contract's limit) are sent in full, compressed.
    let listing = packages::parse(&synthetic_output(MAX_PACKAGES));
    let encoded = encode(
        "00000000-0000-4000-8000-000000000001",
        "2026-01-01T12:00:00Z",
        &Collected::Dpkg(listing),
    );
    assert!(encoded.refused.is_none());
    assert!(
        encoded.json_bytes < MAX_JSON_BYTES,
        "{}",
        encoded.json_bytes
    );
    assert!(
        encoded.body.len() < MAX_GZIP_BYTES / 4,
        "{}",
        encoded.body.len()
    );
    let body = gunzip(&encoded.body);
    assert_eq!(body["packages"].as_array().unwrap().len(), MAX_PACKAGES);
}

fn synthetic_host(count: usize) -> FakeHost {
    FakeHost::default()
        .with_stat(DPKG_STATUS, 0o644, 0, 0)
        .with_output("dpkg-query --show", Ok(synthetic_output(count)))
}

#[test]
fn peak_memory_for_3000_packages_stays_modest() {
    // P2-AGENT-PACKAGES: measured and noted (docs/operations/agent-packages.md). From the command's
    // output to the compressed body, on this thread; the fake host hands over the output once, as the
    // real host's reader thread does.
    let host = synthetic_host(3000);
    let output_bytes = synthetic_output(3000).len();
    let (encoded, peak) = memory::on_this_thread(|| {
        let collected = packages::collect(&host, None);
        encode(
            "00000000-0000-4000-8000-000000000001",
            "2026-01-01T12:00:00Z",
            &collected,
        )
    });
    println!(
        "3000 packages: dpkg-query output {output_bytes} bytes, JSON {} bytes, gzip {} bytes; peak heap {peak} bytes",
        encoded.json_bytes,
        encoded.body.len()
    );
    assert!(encoded.refused.is_none());
    assert!(peak < 2 * 1024 * 1024, "peak heap {peak} bytes");
}

#[test]
#[ignore = "measures the whole process: run alone with --ignored --test-threads=1 on a dpkg system"]
fn peak_memory_with_the_real_dpkg_query() {
    // The same pipeline with the real RealHost (its reader threads included) and the real dpkg-query
    // on a 3,000-package database:
    //   cargo test peak_memory -- --ignored --nocapture --test-threads=1
    let host = SyntheticDpkg::new(3000);
    let (encoded, peak) = memory::in_process(|| {
        let collected = packages::collect(&host, None);
        assert!(matches!(collected, Collected::Dpkg(_)), "{collected:?}");
        encode(
            "00000000-0000-4000-8000-000000000001",
            "2026-01-01T12:00:00Z",
            &collected,
        )
    });
    println!(
        "3000 packages with the real dpkg-query: JSON {} bytes, gzip {} bytes; peak heap {peak} bytes",
        encoded.json_bytes,
        encoded.body.len()
    );
    assert!(peak < 4 * 1024 * 1024, "peak heap {peak} bytes");
}
