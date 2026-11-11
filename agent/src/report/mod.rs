//! Heartbeats, inventory reports, configuration reports, and package reports (FR-1.2, FR-1.3, FR-2.1,
//! FR-2.3, P1-AGENT-REPORT, P2-A01, P2-AGENT-PACKAGES).
//!
//! [`run`] drives four loops until shutdown, each on its own thread so a slow collection or a hung
//! request never delays a heartbeat:
//!
//! - the heartbeat loop ([`heartbeat`]): a heartbeat at once, then every heartbeat interval;
//! - the inventory loop ([`inventory`]): a report at once, then on schedule and on stable-fact change;
//! - the config loop ([`config`]): the manifest and a report at once, then every 6 hours;
//! - the packages loop ([`packages`]): a package report at once, then on the config report's interval.
//!
//! The server's `report_request` directive reaches the report loops through [`requests`]: the heartbeat
//! loop raises one request per episode and the report loops poll for it every [`REQUEST_POLL`].
//!
//! All wait with [`Shutdown::wait`], so `SIGTERM` ends them between requests; what is in flight
//! finishes first. The loops stop in parallel, so stopping takes as long as the slowest of them
//! (Rust practice review of #114):
//!
//! - heartbeat: the request in flight, at most the client's 30 s timeout;
//! - config: the one request or collection call in flight, at most 30 s for a request, 10 s for a
//!   command, 5 s for a filesystem call. The reporter checks [`Shutdown`] itself: the collection
//!   starts nothing new, a report collected meanwhile is dropped, and nothing is fetched or sent
//!   after the stop request;
//! - packages: the listing in flight (at most 20 s, then dropped) or the request in flight (30 s);
//!   like the config reporter, it starts nothing after the stop request;
//! - inventory: a collection already started (about 10 s) and its send (30 s), about 40 s.
//!
//! So the agent stops within about 40 s, inside systemd's default 90 s stop timeout (the unit sets
//! no `TimeoutStopSec`). The state record is written atomically
//! after each accepted report, so stopping at any point loses nothing. If any loop ends unexpectedly
//! (a bug that panics), the others are stopped too and the agent exits with a failure, so systemd
//! restarts it rather than leaving it half working.
//!
//! The intervals in force are shared ([`intervals::Intervals`]): the heartbeat loop applies what the
//! server directs, and the inventory loop reads it.

mod config;
mod envelope;
mod heartbeat;
mod intervals;
mod inventory;
mod packages;
mod requests;
mod time;

use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::client::{ApiError, ApiResponse, Client, Conditional};
use crate::collect::Collector;
use crate::config::Config;
use crate::facts::host::{Host, RealHost};
use crate::retry::{Backoff, RetryPolicy, Rng, SplitMix64};
use crate::shutdown::Shutdown;
use crate::tasks::executor::Registry;
use crate::tasks::poller::{Poller, TaskHint};
use crate::tasks::wire::Api as TasksApi;
use crate::update::Updater;

pub use heartbeat::{ACK_RECORD, Ack, HEARTBEAT_PATH, Heartbeat, HeartbeatRequest};
pub use intervals::Intervals;
pub use inventory::Reporter;
use requests::{ReportRequests, ReportType};
pub use time::rfc3339;

/// How often a report loop looks for a `report_request` the heartbeat loop raised.
pub const REQUEST_POLL: Duration = Duration::from_secs(5);

/// Sends one JSON request. [`Client`] in production; a scripted fake in tests.
pub trait Transport {
    fn post(&self, path: &str, body: &serde_json::Value) -> Result<ApiResponse, ApiError>;

    /// POSTs a gzip-compressed JSON body with `Content-Encoding: gzip` (the package report). Required,
    /// like the GET below.
    fn post_gzip(&self, path: &str, gzipped: &[u8]) -> Result<ApiResponse, ApiError>;

    /// GETs a JSON document with an optional `If-None-Match` (the config manifest). Required, so a
    /// transport cannot forget it and fail only at run time.
    fn get_conditional(&self, path: &str, etag: Option<&str>) -> Result<Conditional, ApiError>;
}

impl Transport for Client {
    fn post(&self, path: &str, body: &serde_json::Value) -> Result<ApiResponse, ApiError> {
        self.post_json(path, body)
    }

    fn post_gzip(&self, path: &str, gzipped: &[u8]) -> Result<ApiResponse, ApiError> {
        self.post_gzip_json(path, gzipped)
    }

    fn get_conditional(&self, path: &str, etag: Option<&str>) -> Result<Conditional, ApiError> {
        self.get_json_conditional(path, etag)
    }
}

/// Runs all loops until `shutdown` is requested. Returns `false` if a loop ended unexpectedly.
pub fn run(
    config: &Config,
    client: &Client,
    shutdown: &Shutdown,
    started: Instant,
    updater: &Updater,
) -> bool {
    run_with(
        config,
        client,
        shutdown,
        started,
        &Collector::new(),
        &RealHost::new(),
        updater,
    )
}

/// [`run`] with the transport, collector and fact reader's host given (tests).
fn run_with(
    config: &Config,
    transport: &(dyn Transport + Sync),
    shutdown: &Shutdown,
    started: Instant,
    collector: &Collector,
    host: &dyn Host,
    updater: &Updater,
) -> bool {
    let intervals = Intervals::new(config.heartbeat, config.inventory);
    let intervals = &intervals;
    let requests = ReportRequests::new();
    let requests = &requests;
    let hint = TaskHint::default();
    let hint = &hint;
    thread::scope(|scope| {
        let heartbeat = spawn_loop(scope, "heartbeat", || {
            let _stop = StopOnExit(shutdown);
            heartbeat_loop(
                intervals, config, transport, shutdown, started, updater, requests, hint,
            );
        });
        let inventory = spawn_loop(scope, "inventory", || {
            let _stop = StopOnExit(shutdown);
            inventory_loop(
                intervals,
                &config.state_dir,
                collector,
                transport,
                shutdown,
                requests,
            );
        });
        let config_report = spawn_loop(scope, "config", || {
            let _stop = StopOnExit(shutdown);
            config_loop(
                config.config_report.start,
                host,
                transport,
                shutdown,
                requests,
            );
        });
        // FR-2.3: packages on the same cadence as the configuration report.
        let packages_report = spawn_loop(scope, "packages", || {
            let _stop = StopOnExit(shutdown);
            packages_loop(
                config.config_report.start,
                host,
                transport,
                shutdown,
                requests,
            );
        });
        // P3-A02: the task poller. It opens the ledger and reports any task left unreported, and
        // polls only when a type is enabled and supported (none in this build: P3-A03's registry is
        // empty until the task types are built).
        let tasks = spawn_loop(scope, "tasks", || {
            let _stop = StopOnExit(shutdown);
            tasks_loop(config, transport, shutdown, updater, hint);
        });
        let handles = [
            ("heartbeat", heartbeat),
            ("inventory", inventory),
            ("config", config_report),
            ("packages", packages_report),
            ("tasks", tasks),
        ];
        // A loop that could not start never runs its StopOnExit, and the others (the heartbeat loop
        // above all) run until shutdown: stop them now, before waiting on any of them, so the agent
        // exits with a failure for systemd to restart instead of running half working (review of #117).
        if handles.iter().any(|(_, handle)| handle.is_err()) {
            shutdown.request();
        }
        let mut clean = true;
        for (name, handle) in handles {
            match handle {
                Ok(handle) => {
                    if handle.join().is_err() {
                        tracing::error!(
                            loop_name = name,
                            "the {name} loop failed; stopping the agent"
                        );
                        clean = false;
                    }
                }
                Err(e) => {
                    tracing::error!(loop_name = name, "cannot start the {name} loop: {e}");
                    shutdown.request();
                    clean = false;
                }
            }
        }
        clean
    })
}

/// Starts the thread of one loop, `fleet-agent-<name>`.
fn spawn_loop<'scope, 'env>(
    scope: &'scope thread::Scope<'scope, 'env>,
    name: &'static str,
    f: impl FnOnce() + Send + 'scope,
) -> io::Result<thread::ScopedJoinHandle<'scope, ()>> {
    #[cfg(test)]
    if tests::FAIL_SPAWN.with(|fail| fail.get() == Some(name)) {
        return Err(io::Error::other("simulated: no thread could be started"));
    }
    thread::Builder::new()
        .name(format!("fleet-agent-{name}"))
        .spawn_scoped(scope, f)
}

/// Requests shutdown when dropped, including when a loop panics, so the other loop stops too.
struct StopOnExit<'a>(&'a Shutdown);

impl Drop for StopOnExit<'_> {
    fn drop(&mut self) {
        self.0.request();
    }
}

#[allow(clippy::too_many_arguments)]
fn heartbeat_loop(
    intervals: &Intervals,
    config: &Config,
    transport: &dyn Transport,
    shutdown: &Shutdown,
    started: Instant,
    updater: &Updater,
    requests: &ReportRequests,
    hint: &TaskHint,
) {
    let mut heartbeat = Heartbeat::new(
        intervals,
        Backoff::new(RetryPolicy::default(), seeded(1)),
        seeded(2),
        started,
    )
    .record_first_ack_in(config.state_dir.clone())
    .with_updater(updater)
    .with_requests(requests)
    .with_capabilities(crate::tasks::Capabilities::of(&config.tasks))
    .with_task_hint(hint);
    while !shutdown.is_requested() {
        let hostname = crate::collect::hostname();
        let wait = heartbeat.beat(transport, hostname, Instant::now(), SystemTime::now());
        // Outcomes of updates wait on disk until the server accepts them; an update in progress with
        // no supervisor gets one. Both are cheap when there is nothing to do.
        updater.tick(transport);
        if shutdown.wait(wait) {
            break;
        }
    }
}

fn tasks_loop(
    config: &Config,
    transport: &dyn Transport,
    shutdown: &Shutdown,
    updater: &Updater,
    hint: &TaskHint,
) {
    // P3-A03: the registry of implemented task types (none in this build, `tasks::IMPLEMENTED`).
    let executor = Registry::production(config.tasks.clone());
    let api = TasksApi(transport);
    let mut poller = Poller::new(
        &config.state_dir,
        &config.tasks,
        &executor,
        Some(updater),
        shutdown,
        hint,
        config.task_poll,
        Backoff::new(RetryPolicy::default(), seeded(9)),
    );
    while !shutdown.is_requested() {
        let wait = poller.tick(&api, Instant::now(), SystemTime::now());
        if shutdown.wait(wait) {
            break;
        }
    }
}

fn inventory_loop(
    intervals: &Intervals,
    state_dir: &Path,
    collector: &Collector,
    transport: &dyn Transport,
    shutdown: &Shutdown,
    requests: &ReportRequests,
) {
    let mut reporter = Reporter::new(
        intervals,
        state_dir.to_owned(),
        Backoff::new(RetryPolicy::default(), seeded(3)),
        seeded(4),
    );
    while !shutdown.is_requested() {
        if requests.take(ReportType::Inventory).is_some() {
            reporter.request();
        }
        let wake = reporter.tick(Instant::now(), &mut || collector.collect(), transport);
        if reporter.take_answered() {
            requests.answered(ReportType::Inventory, Instant::now());
        }
        let wait = wake
            .saturating_duration_since(Instant::now())
            .min(REQUEST_POLL);
        if shutdown.wait(wait) {
            break;
        }
    }
}

fn config_loop(
    interval: Duration,
    host: &dyn Host,
    transport: &dyn Transport,
    shutdown: &Shutdown,
    requests: &ReportRequests,
) {
    let mut reporter = config::Reporter::new(
        host,
        interval,
        Backoff::new(RetryPolicy::default(), seeded(5)),
        seeded(6),
    )
    .stopping_on(shutdown);
    while !shutdown.is_requested() {
        if requests.take(ReportType::Config).is_some() {
            reporter.request();
        }
        let wake = reporter.tick(Instant::now(), transport);
        if reporter.take_answered() {
            requests.answered(ReportType::Config, Instant::now());
        }
        let wait = wake
            .saturating_duration_since(Instant::now())
            .min(REQUEST_POLL);
        if shutdown.wait(wait) {
            break;
        }
    }
}

fn packages_loop(
    interval: Duration,
    host: &dyn Host,
    transport: &dyn Transport,
    shutdown: &Shutdown,
    requests: &ReportRequests,
) {
    let mut reporter = packages::Reporter::new(
        host,
        interval,
        Backoff::new(RetryPolicy::default(), seeded(7)),
        seeded(8),
    )
    .stopping_on(shutdown);
    while !shutdown.is_requested() {
        if requests.take(ReportType::Packages).is_some() {
            reporter.request();
        }
        let wake = reporter.tick(Instant::now(), transport);
        if reporter.take_answered() {
            requests.answered(ReportType::Packages, Instant::now());
        }
        let wait = wake
            .saturating_duration_since(Instant::now())
            .min(REQUEST_POLL);
        if shutdown.wait(wait) {
            break;
        }
    }
}

/// When a failure in a tick that began at the (simulated) `now` happened: `now` moved on by the real
/// time since `tick_started`. A backoff or `Retry-After` delay is a wait *after* the failure, so it is
/// counted from here; counted from `now`, a request that took its whole 30 s timeout would have used
/// up a 5 s backoff and been retried at once (review of #117). Tests drive `now` by hand and lose only
/// the few real milliseconds a tick takes.
fn failed_at(now: Instant, tick_started: Instant) -> Instant {
    now + tick_started.elapsed()
}

/// A jitter source per use, so the streams differ.
fn seeded(stream: u64) -> SplitMix64 {
    let mut base = SplitMix64::from_entropy();
    SplitMix64::new(base.next_u64() ^ stream.wrapping_mul(0x9E37_79B9_7F4A_7C15))
}

/// `interval` minus a random amount up to 10% of it: spreads a fleet's requests without ever waiting
/// longer than the interval.
fn jittered(interval: Duration, rng: &mut impl Rng) -> Duration {
    let spread = (interval / 10).as_millis() as u64;
    if spread == 0 {
        return interval;
    }
    interval - Duration::from_millis(rng.next_u64() % (spread + 1))
}

/// A new report id: a random (version 4) UUID from the kernel's random source (`getrandom(2)`, so no
/// device file is needed under systemd sandboxing).
pub(crate) fn new_report_id() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(uuid_v4(bytes))
}

/// Formats 16 random bytes as a version 4, RFC 4122 variant UUID (RFC 9562, section 5.4).
fn uuid_v4(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let h = crate::release::hex(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// Remembers which messages were already logged, so a server that repeats an unknown directive on
/// every heartbeat produces one log line, not one a minute. Bounded: past the limit, nothing new is
/// remembered and repeats are logged again rather than growing memory.
#[derive(Default)]
struct Notes(HashSet<String>);

impl Notes {
    const LIMIT: usize = 256;

    /// `true` the first time `note` is seen.
    fn first(&mut self, note: &str) -> bool {
        if self.0.contains(note) {
            return false;
        }
        if self.0.len() < Self::LIMIT {
            self.0.insert(note.to_owned());
        }
        true
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::client::tests::trusting_client;
    use crate::config::tests as cfg;
    use crate::test_support::{TempDir, TestPki, TlsServer};
    use std::cell::RefCell;
    use std::collections::VecDeque;

    type Reply = Box<dyn FnOnce(&serde_json::Value) -> Result<ApiResponse, ApiError>>;

    /// A scripted transport: answers from a queue and records every request. With the queue empty it
    /// accepts the request as the real server would if `accepting`, and otherwise fails as if the
    /// server were down.
    pub struct FakeTransport {
        replies: RefCell<VecDeque<Reply>>,
        accepting: std::cell::Cell<bool>,
        sent: RefCell<Vec<(String, serde_json::Value)>>,
        gets: RefCell<VecDeque<Result<Conditional, ApiError>>>,
        /// The `If-None-Match` of every GET, in order.
        got: RefCell<Vec<Option<String>>>,
        /// The paths of the requests sent gzip-compressed, in order.
        gzipped: RefCell<Vec<String>>,
    }

    impl FakeTransport {
        pub fn new(replies: Vec<Result<ApiResponse, ApiError>>) -> Self {
            let transport = Self {
                replies: RefCell::default(),
                accepting: std::cell::Cell::new(false),
                sent: RefCell::default(),
                gets: RefCell::default(),
                got: RefCell::default(),
                gzipped: RefCell::default(),
            };
            for reply in replies {
                transport.push(reply);
            }
            transport
        }

        pub fn push(&self, reply: Result<ApiResponse, ApiError>) {
            self.push_with(move |_| reply);
        }

        /// Queues a reply computed from the request body.
        pub fn push_with(
            &self,
            reply: impl FnOnce(&serde_json::Value) -> Result<ApiResponse, ApiError> + 'static,
        ) {
            self.replies.borrow_mut().push_back(Box::new(reply));
        }

        pub fn set_accepting(&self, accepting: bool) {
            self.accepting.set(accepting);
        }

        /// Queues the answer to the next GET.
        pub fn push_get(&self, reply: Result<Conditional, ApiError>) {
            self.gets.borrow_mut().push_back(reply);
        }

        pub fn gets(&self) -> Vec<Option<String>> {
            self.got.borrow().clone()
        }

        pub fn sent(&self) -> Vec<(String, serde_json::Value)> {
            self.sent.borrow().clone()
        }

        /// The paths of the requests that were sent gzip-compressed.
        pub fn gzipped(&self) -> Vec<String> {
            self.gzipped.borrow().clone()
        }
    }

    impl Transport for FakeTransport {
        fn post(&self, path: &str, body: &serde_json::Value) -> Result<ApiResponse, ApiError> {
            self.sent.borrow_mut().push((path.to_owned(), body.clone()));
            let next = self.replies.borrow_mut().pop_front();
            match next {
                Some(reply) => reply(body),
                None if self.accepting.get() => {
                    if path == heartbeat::HEARTBEAT_PATH {
                        ok(
                            serde_json::json!({"server_time": "2026-01-01T12:00:00Z", "directives": {}}),
                        )
                    } else if path == config::CONFIG_PATH {
                        ok(serde_json::json!({
                            "report_id": body["report_id"],
                            "duplicate": false,
                            "manifest_version": body["manifest_version"],
                        }))
                    } else {
                        ok(serde_json::json!({"report_id": body["report_id"], "duplicate": false}))
                    }
                }
                None => Err(ApiError::Transport("connection refused".into())),
            }
        }

        /// Decompresses and parses the body as the server would, then answers like [`Self::post`]; a
        /// body that is not gzip of JSON fails the test.
        fn post_gzip(&self, path: &str, gzipped: &[u8]) -> Result<ApiResponse, ApiError> {
            use std::io::Read;
            let mut json = Vec::new();
            flate2::read::GzDecoder::new(gzipped)
                .read_to_end(&mut json)
                .expect("a gzip body");
            let body: serde_json::Value = serde_json::from_slice(&json).expect("gzip of JSON");
            self.gzipped.borrow_mut().push(path.to_owned());
            self.post(path, &body)
        }

        fn get_conditional(
            &self,
            _path: &str,
            etag: Option<&str>,
        ) -> Result<Conditional, ApiError> {
            self.got.borrow_mut().push(etag.map(str::to_owned));
            match self.gets.borrow_mut().pop_front() {
                Some(reply) => reply,
                None if self.accepting.get() && etag.is_some() => Ok(Conditional::NotModified),
                None if self.accepting.get() => Ok(Conditional::Modified {
                    body: crate::facts::fake::server_manifest(),
                    etag: Some("\"m1\"".into()),
                }),
                None => Err(ApiError::Transport("connection refused".into())),
            }
        }
    }

    pub fn ok(body: serde_json::Value) -> Result<ApiResponse, ApiError> {
        Ok(ApiResponse {
            status: 200,
            body,
            request_id: Some("00000000-0000-4000-8000-0000000000aa".into()),
        })
    }

    #[test]
    fn report_ids_are_random_uuid_v4() {
        let pattern = |id: &str| {
            let b = id.as_bytes();
            id.len() == 36
                && [8, 13, 18, 23].iter().all(|&i| b[i] == b'-')
                && b[14] == b'4'
                && matches!(b[19], b'8' | b'9' | b'a' | b'b')
                && id
                    .chars()
                    .all(|c| c == '-' || c.is_ascii_digit() || ('a'..='f').contains(&c))
        };
        let ids: HashSet<String> = (0..1000).map(|_| new_report_id().unwrap()).collect();
        assert_eq!(ids.len(), 1000);
        assert!(ids.iter().all(|id| pattern(id)), "{ids:?}");
        assert_eq!(uuid_v4([0xff; 16]), "ffffffff-ffff-4fff-bfff-ffffffffffff");
        assert_eq!(uuid_v4([0; 16]), "00000000-0000-4000-8000-000000000000");
        // Python's uuid.UUID(bytes=...) of the same bytes, with the version and variant bits set.
        let counting: [u8; 16] = std::array::from_fn(|i| i as u8);
        assert_eq!(uuid_v4(counting), "00010203-0405-4607-8809-0a0b0c0d0e0f");
    }

    #[test]
    fn jitter_stays_within_ten_percent_below() {
        let mut rng = SplitMix64::new(5);
        let waits: Vec<_> = (0..500)
            .map(|_| jittered(Duration::from_secs(60), &mut rng))
            .collect();
        assert!(
            waits
                .iter()
                .all(|w| *w >= Duration::from_secs(54) && *w <= Duration::from_secs(60))
        );
        assert!(waits.iter().collect::<HashSet<_>>().len() > 100);
        assert_eq!(
            jittered(Duration::from_millis(5), &mut rng),
            Duration::from_millis(5)
        );
    }

    #[test]
    fn notes_are_bounded() {
        let mut notes = Notes::default();
        assert!(notes.first("a"));
        assert!(!notes.first("a"));
        for i in 0..1000 {
            notes.first(&i.to_string());
        }
        assert_eq!(notes.0.len(), Notes::LIMIT);
    }

    /// A [`TlsServer`] reply for whichever endpoint a request was for.
    fn reply_for(request: &str) -> String {
        let body = if request.starts_with("POST /api/v1/heartbeat ") {
            r#"{"server_time":"2026-01-01T12:00:00Z","directives":{}}"#.to_owned()
        } else if request.starts_with("GET /api/v1/manifest/config ") {
            return crate::test_support::http_reply(
                "200 OK",
                &["X-Request-Id: req-1", "ETag: \"m1\""],
                &crate::facts::fake::server_manifest().to_string(),
            );
        } else if request.starts_with("POST /api/v1/reports/config ") {
            let id = request
                .split("\"report_id\":\"")
                .nth(1)
                .and_then(|rest| rest.get(..36))
                .unwrap_or("");
            let version = crate::facts::fake::server_manifest()["manifest_version"].clone();
            format!(r#"{{"report_id":"{id}","duplicate":false,"manifest_version":{version}}}"#)
        } else {
            let id = request
                .split("\"report_id\":\"")
                .nth(1)
                .and_then(|rest| rest.get(..36))
                .unwrap_or("");
            format!(r#"{{"report_id":"{id}","duplicate":false}}"#)
        };
        crate::test_support::http_reply("200 OK", &["X-Request-Id: req-1"], &body)
    }

    #[test]
    fn run_reports_over_https_at_once_and_stops_cleanly() {
        // The real client, a local TLS server, and this machine's collectors: the first heartbeat and
        // the startup report reach the server within seconds (AC: "first heartbeat within seconds").
        let pki = TestPki::generate();
        let dir = TempDir::new();
        let server = TlsServer::serve(&pki, 5, reply_for);
        let client = trusting_client(&server, &pki, &dir);
        let state_dir = dir.path("state");
        crate::state::ensure_dir(&state_dir).unwrap();
        let config = Config {
            state_dir: state_dir.clone(),
            ..Config::from_toml(&cfg::minimal()).unwrap()
        };
        let shutdown = Shutdown::default();
        let started = Instant::now();
        let (clean, requests) = thread::scope(|scope| {
            let runner = scope.spawn(|| {
                run_with(
                    &config,
                    &client,
                    &shutdown,
                    started,
                    &Collector::new(),
                    &crate::facts::fake::FakeHost::debian13(),
                    &Updater::inert(&state_dir),
                )
            });
            let requests = server.finish();
            // Both requests arrived; the record is written right after the report is accepted.
            let deadline = Instant::now() + Duration::from_secs(10);
            while !state_dir.join(inventory::RECORD_NAME).exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            shutdown.request();
            (runner.join().unwrap(), requests)
        });
        assert!(clean);
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "took {:?}",
            started.elapsed()
        );
        assert_eq!(requests.len(), 5, "{requests:?}");
        let mut saw_config = false;
        let mut saw_packages = false;
        for request in &requests {
            let (head, body) = request.split_once("\r\n\r\n").unwrap();
            if head.starts_with("GET /api/v1/manifest/config ") {
                continue;
            }
            let body: serde_json::Value = serde_json::from_str(body).unwrap();
            if head.starts_with("POST /api/v1/heartbeat ") {
                crate::collect::contract::assert_conforms("v1", "heartbeat.request", &body);
            } else if head.starts_with("POST /api/v1/reports/config ") {
                // P2-A01: what the agent really sends over TLS conforms to the contract.
                crate::collect::contract::assert_conforms("v1", "config.request", &body);
                saw_config = true;
            } else if head.starts_with("POST /api/v1/reports/packages ") {
                // P2-AGENT-PACKAGES: compressed on the wire, and the fake host's dpkg listing in full.
                assert!(
                    head.to_ascii_lowercase().contains("content-encoding: gzip"),
                    "{head}"
                );
                crate::collect::contract::assert_conforms("v1", "packages.request", &body);
                assert_eq!(body["manager"], "dpkg");
                assert_eq!(body["packages"].as_array().unwrap().len(), 29);
                saw_packages = true;
            } else {
                assert!(
                    head.starts_with("POST /api/v1/reports/inventory "),
                    "{head}"
                );
                crate::collect::contract::assert_conforms("v1", "inventory.request", &body);
            }
        }
        assert!(saw_config && saw_packages, "{requests:?}");
        let record: inventory::Record =
            serde_json::from_slice(&std::fs::read(state_dir.join(inventory::RECORD_NAME)).unwrap())
                .unwrap();
        assert_eq!(record.agent_version, crate::AGENT_VERSION);
    }

    #[test]
    fn a_failed_loop_stops_the_agent() {
        // A transport that panics stands in for a bug in one loop: the other loop must not keep the
        // agent half alive.
        struct Panicking;
        impl Transport for Panicking {
            fn post(&self, path: &str, _: &serde_json::Value) -> Result<ApiResponse, ApiError> {
                if path == heartbeat::HEARTBEAT_PATH {
                    panic!("simulated bug");
                }
                Err(ApiError::Transport("down".into()))
            }

            fn post_gzip(&self, _: &str, _: &[u8]) -> Result<ApiResponse, ApiError> {
                Err(ApiError::Transport("down".into()))
            }

            fn get_conditional(&self, _: &str, _: Option<&str>) -> Result<Conditional, ApiError> {
                Err(ApiError::Transport("down".into()))
            }
        }
        let dir = TempDir::new();
        let config = Config {
            state_dir: dir.path("state"),
            ..Config::from_toml(&cfg::minimal()).unwrap()
        };
        let shutdown = Shutdown::default();
        let collector = Collector::new();
        let started = Instant::now();
        let updater = Updater::inert(&config.state_dir);
        let host = crate::facts::fake::FakeHost::debian13();
        let clean = run_with(
            &config, &Panicking, &shutdown, started, &collector, &host, &updater,
        );
        assert!(!clean);
        assert!(shutdown.is_requested());
        assert!(started.elapsed() < Duration::from_secs(30));
    }

    thread_local! {
        /// Makes [`spawn_loop`] fail for the loop of this name, on this thread, as a thread limit would.
        pub(super) static FAIL_SPAWN: std::cell::Cell<Option<&'static str>> =
            const { std::cell::Cell::new(None) };
    }

    #[test]
    fn a_loop_that_cannot_start_stops_the_agent_at_once() {
        // Review of #117: a failed spawn was only seen after joining the loops before it, and the
        // heartbeat loop runs until shutdown, so the agent kept running without that loop. Every loop
        // is tried, the heartbeat's included.
        struct Down;
        impl Transport for Down {
            fn post(&self, _: &str, _: &serde_json::Value) -> Result<ApiResponse, ApiError> {
                Err(ApiError::Transport("down".into()))
            }
            fn post_gzip(&self, _: &str, _: &[u8]) -> Result<ApiResponse, ApiError> {
                Err(ApiError::Transport("down".into()))
            }
            fn get_conditional(&self, _: &str, _: Option<&str>) -> Result<Conditional, ApiError> {
                Err(ApiError::Transport("down".into()))
            }
        }
        for name in ["heartbeat", "inventory", "config", "packages"] {
            let dir = TempDir::new();
            let config = Config {
                state_dir: dir.path("state"),
                ..Config::from_toml(&cfg::minimal()).unwrap()
            };
            let shutdown = Shutdown::default();
            let (done, finished) = std::sync::mpsc::channel();
            let outcome = thread::scope(|scope| {
                scope.spawn(|| {
                    FAIL_SPAWN.with(|fail| fail.set(Some(name)));
                    let collector = Collector::new();
                    let updater = Updater::inert(&config.state_dir);
                    let host = crate::facts::fake::FakeHost::debian13();
                    let clean = run_with(
                        &config,
                        &Down,
                        &shutdown,
                        Instant::now(),
                        &collector,
                        &host,
                        &updater,
                    );
                    let _ = done.send(clean);
                });
                let outcome = finished.recv_timeout(Duration::from_secs(20));
                // Unblock the run if it is still going (the old behaviour), so the test fails, not hangs.
                shutdown.request();
                outcome
            });
            assert_eq!(
                outcome,
                Ok(false),
                "the {name} loop could not start, but the agent kept running"
            );
        }
    }
}
