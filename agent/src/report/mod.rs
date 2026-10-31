//! Heartbeats and inventory reports (FR-1.2, FR-1.3, P1-AGENT-REPORT).
//!
//! [`run`] drives two loops until shutdown, each on its own thread so a slow collection or a hung
//! inventory request never delays a heartbeat:
//!
//! - the heartbeat loop ([`heartbeat`]): a heartbeat at once, then every heartbeat interval;
//! - the inventory loop ([`inventory`]): a report at once, then on schedule and on stable-fact change.
//!
//! Both wait with [`Shutdown::wait`], so `SIGTERM` ends them between requests; a request already in
//! flight finishes first (at most the client's 30 s timeout). The state record is written atomically
//! after each accepted report, so stopping at any point loses nothing. If either loop ends unexpectedly
//! (a bug that panics), the other is stopped too and the agent exits with a failure, so systemd
//! restarts it rather than leaving it half working.
//!
//! The intervals in force are shared ([`intervals::Intervals`]): the heartbeat loop applies what the
//! server directs, and the inventory loop reads it.

mod envelope;
mod heartbeat;
mod intervals;
mod inventory;
mod time;

use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::client::{ApiError, ApiResponse, Client};
use crate::collect::Collector;
use crate::config::Config;
use crate::retry::{Backoff, RetryPolicy, Rng, SplitMix64};
use crate::shutdown::Shutdown;

pub use heartbeat::{ACK_RECORD, Ack, HEARTBEAT_PATH, Heartbeat, HeartbeatRequest};
pub use intervals::Intervals;
pub use inventory::Reporter;
pub use time::rfc3339;

/// Sends one JSON request. [`Client`] in production; a scripted fake in tests.
pub trait Transport {
    fn post(&self, path: &str, body: &serde_json::Value) -> Result<ApiResponse, ApiError>;
}

impl Transport for Client {
    fn post(&self, path: &str, body: &serde_json::Value) -> Result<ApiResponse, ApiError> {
        self.post_json(path, body)
    }
}

/// Runs both loops until `shutdown` is requested. Returns `false` if a loop ended unexpectedly.
pub fn run(config: &Config, client: &Client, shutdown: &Shutdown, started: Instant) -> bool {
    run_with(config, client, shutdown, started, &Collector::new())
}

/// [`run`] with the transport and collector given (tests).
fn run_with(
    config: &Config,
    transport: &(dyn Transport + Sync),
    shutdown: &Shutdown,
    started: Instant,
    collector: &Collector,
) -> bool {
    let intervals = Intervals::new(config.heartbeat, config.inventory);
    let intervals = &intervals;
    thread::scope(|scope| {
        let heartbeat = thread::Builder::new()
            .name("fleet-agent-heartbeat".into())
            .spawn_scoped(scope, || {
                let _stop = StopOnExit(shutdown);
                heartbeat_loop(intervals, &config.state_dir, transport, shutdown, started);
            });
        let inventory = thread::Builder::new()
            .name("fleet-agent-inventory".into())
            .spawn_scoped(scope, || {
                let _stop = StopOnExit(shutdown);
                inventory_loop(intervals, &config.state_dir, collector, transport, shutdown);
            });
        let mut clean = true;
        for (name, handle) in [("heartbeat", heartbeat), ("inventory", inventory)] {
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

/// Requests shutdown when dropped, including when a loop panics, so the other loop stops too.
struct StopOnExit<'a>(&'a Shutdown);

impl Drop for StopOnExit<'_> {
    fn drop(&mut self) {
        self.0.request();
    }
}

fn heartbeat_loop(
    intervals: &Intervals,
    state_dir: &Path,
    transport: &dyn Transport,
    shutdown: &Shutdown,
    started: Instant,
) {
    let mut heartbeat = Heartbeat::new(
        intervals,
        Backoff::new(RetryPolicy::default(), seeded(1)),
        seeded(2),
        started,
    )
    .record_first_ack_in(state_dir.to_owned());
    while !shutdown.is_requested() {
        let hostname = crate::collect::hostname();
        let wait = heartbeat.beat(transport, hostname, Instant::now(), SystemTime::now());
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
) {
    let mut reporter = Reporter::new(
        intervals,
        state_dir.to_owned(),
        Backoff::new(RetryPolicy::default(), seeded(3)),
        seeded(4),
    );
    while !shutdown.is_requested() {
        let wake = reporter.tick(Instant::now(), &mut || collector.collect(), transport);
        if shutdown.wait(wake.saturating_duration_since(Instant::now())) {
            break;
        }
    }
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
fn new_report_id() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(uuid_v4(bytes))
}

/// Formats 16 random bytes as a version 4, RFC 4122 variant UUID.
fn uuid_v4(bytes: [u8; 16]) -> String {
    uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .hyphenated()
        .to_string()
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
    }

    impl FakeTransport {
        pub fn new(replies: Vec<Result<ApiResponse, ApiError>>) -> Self {
            let transport = Self {
                replies: RefCell::default(),
                accepting: std::cell::Cell::new(false),
                sent: RefCell::default(),
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

        pub fn sent(&self) -> Vec<(String, serde_json::Value)> {
            self.sent.borrow().clone()
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
                    } else {
                        ok(serde_json::json!({"report_id": body["report_id"], "duplicate": false}))
                    }
                }
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
        } else {
            let id = request
                .split("\"report_id\":\"")
                .nth(1)
                .and_then(|rest| rest.get(..36))
                .unwrap_or("");
            format!(r#"{{"report_id":"{id}","duplicate":false}}"#)
        };
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Request-Id: req-1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn run_reports_over_https_at_once_and_stops_cleanly() {
        // The real client, a local TLS server, and this machine's collectors: the first heartbeat and
        // the startup report reach the server within seconds (AC: "first heartbeat within seconds").
        let pki = TestPki::generate();
        let dir = TempDir::new();
        let server = TlsServer::serve(&pki, 2, reply_for);
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
            let runner =
                scope.spawn(|| run_with(&config, &client, &shutdown, started, &Collector::new()));
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
        assert_eq!(requests.len(), 2, "{requests:?}");
        for request in &requests {
            let (head, body) = request.split_once("\r\n\r\n").unwrap();
            let body: serde_json::Value = serde_json::from_str(body).unwrap();
            if head.starts_with("POST /api/v1/heartbeat ") {
                crate::collect::contract::assert_conforms("v1", "heartbeat.request", &body);
            } else {
                assert!(
                    head.starts_with("POST /api/v1/reports/inventory "),
                    "{head}"
                );
                crate::collect::contract::assert_conforms("v1", "inventory.request", &body);
            }
        }
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
        }
        let dir = TempDir::new();
        let config = Config {
            state_dir: dir.path("state"),
            ..Config::from_toml(&cfg::minimal()).unwrap()
        };
        let shutdown = Shutdown::default();
        let collector = Collector::new();
        let started = Instant::now();
        let clean = run_with(&config, &Panicking, &shutdown, started, &collector);
        assert!(!clean);
        assert!(shutdown.is_requested());
        assert!(started.elapsed() < Duration::from_secs(30));
    }
}
