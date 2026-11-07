//! Config reporter tests with a scripted transport, simulated time, and a recording fake host
//! (P2-A01, FR-2.1): scheduling, retry with the same id, requests, manifest versions, size.

use std::collections::BTreeMap;

use serde_json::json;

use super::*;
use crate::client::ApiResponse;
use crate::collect::contract::assert_conforms;
use crate::facts::fake::{FakeHost, server_manifest};
use crate::report::tests::{FakeTransport, ok};
use crate::retry::{RetryPolicy, SplitMix64};

const INTERVAL: Duration = Duration::from_secs(6 * 3600);

fn reporter(host: &FakeHost) -> Reporter<'_, SplitMix64> {
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

/// The reports posted so far.
fn posts(transport: &FakeTransport) -> Vec<Value> {
    transport
        .sent()
        .into_iter()
        .filter(|(path, _)| path == CONFIG_PATH)
        .map(|(_, body)| body)
        .collect()
}

fn manifest_version() -> u64 {
    server_manifest()["manifest_version"].as_u64().unwrap()
}

fn manifest_at(version: u64) -> Conditional {
    let mut body = server_manifest();
    body["manifest_version"] = json!(version);
    Conditional::Modified {
        body,
        etag: Some(format!("\"m{version}\"")),
    }
}

fn accepted_at(version: u64) -> Result<ApiResponse, ApiError> {
    ok(json!({"report_id": "ignored", "duplicate": false, "manifest_version": version}))
}

fn down() -> Result<ApiResponse, ApiError> {
    Err(ApiError::Transport("connection refused".into()))
}

#[test]
fn the_startup_report_fetches_the_manifest_and_conforms_to_the_contract() {
    let host = FakeHost::debian13();
    let transport = transport();
    let mut reporter = reporter(&host);
    let t0 = Instant::now();
    reporter.tick(t0, &transport);

    assert_eq!(transport.gets(), [None]);
    let sent = posts(&transport);
    assert_eq!(sent.len(), 1);
    assert_conforms("v1", "config.request", &sent[0]);
    assert_eq!(sent[0]["manifest_version"], json!(manifest_version()));
    let listed = crate::facts::fake::server_manifest_parsed().facts.len();
    assert_eq!(sent[0]["facts"].as_object().unwrap().len(), listed);
    assert_eq!(sent[0]["agent_version"], json!(AGENT_VERSION));
    // Nothing the manifest names was run: only the fixed commands the readers know.
    assert!(host.log().iter().all(|entry| !entry.contains("rm ")));
}

#[test]
fn reports_follow_the_interval_less_jitter_and_revalidate_the_manifest() {
    let host = FakeHost::debian13();
    let transport = transport();
    let mut reporter = reporter(&host);
    let t0 = Instant::now();
    reporter.tick(t0, &transport);
    let wake = reporter.tick(t0 + secs(1), &transport);
    assert_eq!(posts(&transport).len(), 1);
    // Due between 90% and 100% of the interval after the first was done.
    let due = wake.duration_since(t0);
    assert!(due <= INTERVAL && due >= INTERVAL * 9 / 10, "{due:?}");

    reporter.tick(t0 + INTERVAL * 89 / 100, &transport);
    assert_eq!(posts(&transport).len(), 1);
    reporter.tick(t0 + INTERVAL + secs(1), &transport);
    assert_eq!(posts(&transport).len(), 2);
    // The second manifest fetch carried the ETag of the first and got a 304.
    assert_eq!(transport.gets(), [None, Some("\"m1\"".to_owned())]);
    // Each report has its own id.
    let sent = posts(&transport);
    assert_ne!(sent[0]["report_id"], sent[1]["report_id"]);
}

#[test]
fn a_failed_send_is_retried_with_the_same_report_id_and_body() {
    let host = FakeHost::debian13();
    let transport = FakeTransport::new(vec![down(), down()]);
    transport.set_accepting(true);
    let mut reporter = reporter(&host);
    let t0 = Instant::now();
    reporter.tick(t0, &transport);
    let id = reporter.pending_report_id().unwrap().to_owned();
    // Not before the backoff has passed.
    reporter.tick(t0 + secs(1), &transport);
    assert_eq!(posts(&transport).len(), 1);
    let mut now = t0;
    for _ in 0..10 {
        now += secs(600);
        reporter.tick(now, &transport);
    }
    let sent = posts(&transport);
    assert!(sent.len() >= 3, "{}", sent.len());
    assert!(sent.iter().all(|b| b["report_id"] == json!(id)));
    assert!(sent.iter().all(|b| b == &sent[0]));
    assert!(reporter.pending_report_id().is_none());
}

#[test]
fn a_request_replaces_a_report_waiting_for_its_retry() {
    let host = FakeHost::debian13();
    let transport = FakeTransport::new(vec![down()]);
    transport.set_accepting(true);
    let mut reporter = reporter(&host);
    let t0 = Instant::now();
    reporter.tick(t0, &transport);
    let first = reporter.pending_report_id().unwrap().to_owned();
    reporter.request();
    reporter.tick(t0 + secs(2), &transport);
    let sent = posts(&transport);
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0]["report_id"], json!(first));
    assert_ne!(sent[1]["report_id"], json!(first));
    assert!(reporter.pending_report_id().is_none());
}

#[test]
fn one_request_gives_exactly_one_extra_report() {
    let host = FakeHost::debian13();
    let transport = transport();
    let mut reporter = reporter(&host);
    let t0 = Instant::now();
    reporter.tick(t0, &transport);
    reporter.request();
    reporter.tick(t0 + secs(10), &transport);
    assert_eq!(posts(&transport).len(), 2);
    for i in 1..20 {
        reporter.tick(t0 + secs(10 + i * 5), &transport);
    }
    assert_eq!(posts(&transport).len(), 2);
}

/// A server that answers the manifest and then the agent is told to stop (SIGTERM mid-tick).
struct StopAfterManifest<'a> {
    inner: &'a FakeTransport,
    stop: &'a crate::shutdown::Shutdown,
}

impl Transport for StopAfterManifest<'_> {
    fn post(&self, path: &str, body: &Value) -> Result<ApiResponse, ApiError> {
        self.inner.post(path, body)
    }

    fn get_conditional(&self, path: &str, etag: Option<&str>) -> Result<Conditional, ApiError> {
        let reply = self.inner.get_conditional(path, etag);
        self.stop.request();
        reply
    }
}

#[test]
fn a_stop_request_mid_tick_starts_no_collection_and_sends_nothing() {
    // Rust practice review of #114: a tick could run a manifest GET, a 65 s collection, and a POST
    // after SIGTERM, past systemd's 90 s stop timeout.
    let host = FakeHost::debian13();
    let inner = transport();
    let stop = crate::shutdown::Shutdown::default();
    let transport = StopAfterManifest {
        inner: &inner,
        stop: &stop,
    };
    let mut reporter = reporter(&host).stopping_on(&stop);
    let t0 = Instant::now();
    reporter.tick(t0, &transport);
    assert_eq!(inner.gets().len(), 1, "the GET in flight finished");
    assert!(
        host.log().is_empty(),
        "collection started: {:?}",
        host.log()
    );
    assert!(posts(&inner).is_empty(), "a report was sent while stopping");
    assert!(
        reporter.pending_report_id().is_none(),
        "nothing kept to send"
    );
    // Nothing more happens on later ticks either.
    reporter.tick(t0 + INTERVAL * 2, &transport);
    assert_eq!(inner.gets().len(), 1);
    assert!(posts(&inner).is_empty());
}

#[test]
fn only_an_accepted_requested_report_answers_the_request() {
    // Review of #114: the request loop learns that the request is over, so a later one is seen.
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
    reporter.tick(t0 + secs(5), &transport);
    assert!(reporter.take_answered());
    assert!(!reporter.take_answered(), "once");
    // A requested report the server rejects answers nothing (it is not repeated either).
    transport.push(Err(ApiError::Rejected {
        status: 422,
        code: "validation_failed".into(),
        message: "no".into(),
        request_id: None,
    }));
    reporter.request();
    reporter.tick(t0 + secs(10), &transport);
    assert!(!reporter.take_answered());
}

#[test]
fn a_newer_manifest_named_by_the_server_is_fetched_and_reported_against_at_once() {
    let host = FakeHost::debian13();
    let v = manifest_version();
    let transport = FakeTransport::new(vec![]);
    transport.set_accepting(true);
    transport.push_get(Ok(manifest_at(v)));
    // The server says it is at v + 1; the refetch really returns v + 1.
    transport.push(accepted_at(v + 1));
    transport.push_get(Ok(manifest_at(v + 1)));
    let mut reporter = reporter(&host);
    let t0 = Instant::now();
    let wake = reporter.tick(t0, &transport);
    assert!(wake <= t0, "a rebuild is wanted at once");
    reporter.tick(t0 + secs(1), &transport);
    let sent = posts(&transport);
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0]["manifest_version"], json!(v));
    assert_eq!(sent[1]["manifest_version"], json!(v + 1));
    assert_conforms("v1", "config.request", &sent[1]);
}

#[test]
fn a_server_ahead_of_its_own_manifest_endpoint_cannot_make_the_agent_loop() {
    let host = FakeHost::debian13();
    let v = manifest_version();
    let transport = FakeTransport::new(vec![]);
    transport.set_accepting(true);
    transport.push_get(Ok(manifest_at(v)));
    transport.push(accepted_at(v + 5));
    transport.push_get(Ok(Conditional::NotModified));
    let mut reporter = reporter(&host);
    let t0 = Instant::now();
    for i in 0..10 {
        reporter.tick(t0 + secs(i * 5), &transport);
    }
    assert_eq!(posts(&transport).len(), 1);
}

#[test]
fn a_report_rejected_for_its_content_is_not_retried() {
    let host = FakeHost::debian13();
    let transport = FakeTransport::new(vec![Err(ApiError::Rejected {
        status: 422,
        code: "validation_failed".into(),
        message: "facts.sshd.port: not an integer".into(),
        request_id: Some("req-1".into()),
    })]);
    transport.set_accepting(true);
    let mut reporter = reporter(&host);
    let t0 = Instant::now();
    reporter.tick(t0, &transport);
    assert!(reporter.pending_report_id().is_none());
    for i in 1..10 {
        reporter.tick(t0 + secs(i * 60), &transport);
    }
    assert_eq!(posts(&transport).len(), 1);
}

#[test]
fn without_a_manifest_nothing_is_sent_and_the_next_try_waits() {
    let host = FakeHost::debian13();
    let transport = FakeTransport::new(vec![]);
    let mut reporter = reporter(&host);
    let t0 = Instant::now();
    let wake = reporter.tick(t0, &transport);
    assert!(posts(&transport).is_empty());
    assert!(wake > t0, "the retry waits for the backoff");
    // The server returns: the report goes out.
    transport.set_accepting(true);
    reporter.tick(wake + secs(1), &transport);
    assert_eq!(posts(&transport).len(), 1);
}

#[test]
fn a_request_survives_an_unreachable_manifest() {
    let host = FakeHost::debian13();
    let transport = transport();
    let mut reporter = reporter(&host);
    let t0 = Instant::now();
    reporter.tick(t0, &transport);
    transport.push_get(Err(ApiError::Transport("down".into())));
    reporter.request();
    // The cached manifest stands in, so the requested report is still sent.
    reporter.tick(t0 + secs(5), &transport);
    assert_eq!(posts(&transport).len(), 2);
}

#[test]
fn a_garbled_manifest_is_not_used() {
    let host = FakeHost::debian13();
    let transport = FakeTransport::new(vec![]);
    transport.set_accepting(true);
    transport.push_get(Ok(Conditional::Modified {
        body: json!({"manifest_version": "one"}),
        etag: None,
    }));
    let mut reporter = reporter(&host);
    reporter.tick(Instant::now(), &transport);
    assert!(posts(&transport).is_empty());
}

#[test]
fn the_body_is_kept_under_the_size_limit_by_turning_the_largest_lists_unreadable() {
    let big = |n: usize| Fact::Ok(json!(vec!["x".repeat(1000); n]));
    let mut facts: BTreeMap<String, Fact> = BTreeMap::new();
    facts.insert("a.huge".into(), big(900));
    facts.insert("b.large".into(), big(200));
    facts.insert("c.small".into(), big(1));
    let (body, shrunk) = build_body("id", "2026-01-01T00:00:00Z", 1, &mut facts);
    assert_eq!(shrunk, 1);
    assert!(serde_json::to_vec(&body).unwrap().len() <= MAX_BODY_BYTES);
    assert_eq!(body["facts"]["a.huge"]["state"], json!("unreadable"));
    assert_eq!(body["facts"]["a.huge"]["value"], Value::Null);
    assert!(body["facts"]["a.huge"]["reason"].as_str().unwrap().len() <= 512);
    assert_eq!(body["facts"]["b.large"]["state"], json!("ok"));
    assert_eq!(body["facts"]["c.small"]["state"], json!("ok"));
}

#[test]
fn a_normal_report_is_far_below_the_size_limit() {
    let host = FakeHost::debian13();
    let transport = transport();
    reporter(&host).tick(Instant::now(), &transport);
    let bytes = serde_json::to_vec(&posts(&transport)[0]).unwrap().len();
    assert!(bytes < 100_000, "{bytes}");
}
