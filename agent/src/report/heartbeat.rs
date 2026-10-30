//! The heartbeat loop (FR-1.2, P1-A06).
//!
//! The first heartbeat goes out as soon as the agent starts. After an accepted heartbeat the next one
//! waits the heartbeat interval in force minus up to 10% jitter (never later than the interval, so
//! liveness thresholds hold); after a failure it waits whatever the retry policy says
//! ([`crate::retry`]), and the interval resumes with the first accepted heartbeat. A failure never ends
//! the loop.
//!
//! Each accepted response is read as an [`Envelope`]: the server's intervals are applied
//! ([`Intervals::apply`]), anything this agent does not understand is ignored and logged once, and a
//! large difference between the server's clock and the agent's is logged when it starts and ends.

use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;

use super::envelope::{self, Envelope};
use super::intervals::Intervals;
use super::time::{parse_rfc3339, rfc3339};
use super::{Notes, Transport, jittered};
use crate::retry::{Backoff, Rng};
use crate::{AGENT_SCHEMA_VERSION, AGENT_VERSION};

pub const HEARTBEAT_PATH: &str = "/api/v1/heartbeat";

/// A clock difference worth telling the operator about: report timestamps use the agent's clock.
const CLOCK_SKEW_WARNING: Duration = Duration::from_secs(5 * 60);

/// `heartbeat.request` (docs/api/schemas/v1).
#[derive(Debug, Serialize)]
pub struct HeartbeatRequest {
    pub schema_version: u32,
    pub agent_version: &'static str,
    pub hostname: Option<String>,
    pub uptime_seconds: u64,
    pub agent_time: String,
}

/// Heartbeat state across iterations of the loop.
pub struct Heartbeat<'a, R: Rng> {
    intervals: &'a Intervals,
    backoff: Backoff<R>,
    rng: R,
    started: Instant,
    accepted_once: bool,
    clock_skewed: bool,
    notes: Notes,
}

impl<'a, R: Rng> Heartbeat<'a, R> {
    /// `started` is when the agent process started, for `uptime_seconds`.
    pub fn new(intervals: &'a Intervals, backoff: Backoff<R>, rng: R, started: Instant) -> Self {
        Self {
            intervals,
            backoff,
            rng,
            started,
            accepted_once: false,
            clock_skewed: false,
            notes: Notes::default(),
        }
    }

    /// The request for one heartbeat.
    pub fn request(
        &self,
        hostname: Option<String>,
        now: Instant,
        wall: SystemTime,
    ) -> HeartbeatRequest {
        HeartbeatRequest {
            schema_version: AGENT_SCHEMA_VERSION,
            agent_version: AGENT_VERSION,
            hostname,
            uptime_seconds: now.saturating_duration_since(self.started).as_secs(),
            agent_time: rfc3339(wall),
        }
    }

    /// Sends one heartbeat and returns how long to wait before the next.
    pub fn beat(
        &mut self,
        transport: &dyn Transport,
        hostname: Option<String>,
        now: Instant,
        wall: SystemTime,
    ) -> Duration {
        let _span = tracing::info_span!("heartbeat").entered();
        let request = self.request(hostname, now, wall);
        let body = match serde_json::to_value(&request) {
            Ok(body) => body,
            // A struct of strings and integers always serialises; keep going if it ever does not.
            Err(e) => {
                tracing::error!("cannot encode the heartbeat: {e}");
                return self.intervals.heartbeat();
            }
        };
        match transport.post(HEARTBEAT_PATH, &body) {
            Ok(response) => {
                let failures = self.backoff.failures();
                self.backoff.on_success();
                let request_id = response.request_id.as_deref().unwrap_or("");
                if !self.accepted_once {
                    tracing::info!(request_id, "first heartbeat accepted by the server");
                } else if failures > 0 {
                    tracing::info!(
                        failed_attempts = failures,
                        request_id,
                        "heartbeats are being accepted again"
                    );
                } else {
                    tracing::debug!(request_id, "heartbeat accepted");
                }
                self.accepted_once = true;
                self.handle(&envelope::parse(&response.body), wall);
                jittered(self.intervals.heartbeat(), &mut self.rng)
            }
            Err(error) => self.backoff.on_failure(&error),
        }
    }

    fn handle(&mut self, envelope: &Envelope, wall: SystemTime) {
        for problem in &envelope.problems {
            if self.notes.first(problem) {
                tracing::warn!(
                    problem = problem.as_str(),
                    "ignoring part of the heartbeat response this agent cannot read"
                );
            }
        }
        for name in &envelope.ignored {
            if self.notes.first(name) {
                tracing::info!(
                    ignored = name.as_str(),
                    "ignoring a heartbeat response entry this agent version does not understand"
                );
            }
        }
        self.intervals.apply(envelope.intervals);
        if let Some(update) = &envelope.agent_update {
            // P1-AGENT-UPDATE (#60) hands this directive to the updater. Until then it is only noted.
            let version = update
                .get("version")
                .and_then(serde_json::Value::as_str)
                .map_or_else(String::new, |v| crate::logging::sanitize(v, 64));
            if self.notes.first(&format!("agent_update {version}")) {
                tracing::info!(
                    offered_version = version.as_str(),
                    agent_version = AGENT_VERSION,
                    "the server offered an agent update; this build cannot install updates, so it is ignored"
                );
            }
        }
        self.check_clock(envelope.server_time.as_deref(), wall);
    }

    fn check_clock(&mut self, server_time: Option<&str>, wall: SystemTime) {
        let Some(text) = server_time else { return };
        let Some(server) = parse_rfc3339(text) else {
            if self.notes.first("unreadable server_time") {
                tracing::warn!(
                    server_time = text,
                    "the heartbeat response has a server_time this agent cannot read; ignoring it"
                );
            }
            return;
        };
        let (skew, agent_ahead) = match wall.duration_since(server) {
            Ok(ahead) => (ahead, true),
            Err(behind) => (behind.duration(), false),
        };
        let skewed = skew > CLOCK_SKEW_WARNING;
        if skewed && !self.clock_skewed {
            tracing::warn!(
                skew_seconds = skew.as_secs(),
                agent_ahead,
                server_time = text,
                agent_time = rfc3339(wall).as_str(),
                "this host's clock differs from the server's; report timestamps will be off until the clock is fixed (check time synchronisation)"
            );
        } else if !skewed && self.clock_skewed {
            tracing::info!(
                skew_seconds = skew.as_secs(),
                "this host's clock agrees with the server's again"
            );
        }
        self.clock_skewed = skewed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ApiError;
    use crate::collect::contract::assert_conforms;
    use crate::config::Interval;
    use crate::logging::capture::logs_of;
    use crate::report::tests::{FakeTransport, ok};
    use crate::retry::{RetryPolicy, SplitMix64};
    use serde_json::json;
    use std::time::UNIX_EPOCH;

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

    fn heartbeat(intervals: &Intervals, started: Instant) -> Heartbeat<'_, SplitMix64> {
        Heartbeat::new(
            intervals,
            Backoff::new(RetryPolicy::default(), SplitMix64::new(1)),
            SplitMix64::new(2),
            started,
        )
    }

    fn wall() -> SystemTime {
        UNIX_EPOCH + secs(1_767_268_800)
    }

    fn envelope(directives: serde_json::Value) -> serde_json::Value {
        json!({"server_time": "2026-01-01T12:00:00Z", "directives": directives})
    }

    #[test]
    fn the_request_conforms_to_the_contract() {
        let intervals = intervals();
        let started = Instant::now();
        let hb = heartbeat(&intervals, started);
        for hostname in [Some("vm-01.example.lan".to_owned()), None] {
            let request = hb.request(hostname, started + secs(3601), wall());
            let value = serde_json::to_value(&request).unwrap();
            assert_conforms("v1", "heartbeat.request", &value);
            assert_eq!(value["uptime_seconds"], 3601);
            assert_eq!(value["agent_time"], "2026-01-01T12:00:00.000Z");
            assert_eq!(value["agent_version"], AGENT_VERSION);
        }
    }

    #[test]
    fn an_accepted_heartbeat_waits_the_interval_minus_jitter() {
        let intervals = intervals();
        let started = Instant::now();
        let mut hb = heartbeat(&intervals, started);
        let transport = FakeTransport::new(vec![]);
        let mut waits = Vec::new();
        for _ in 0..50 {
            transport.push(ok(envelope(json!([]))));
            waits.push(hb.beat(&transport, None, started, wall()));
        }
        assert!(
            waits.iter().all(|w| *w >= secs(54) && *w <= secs(60)),
            "{waits:?}"
        );
        assert!(waits.iter().any(|w| *w != waits[0]), "no jitter");
        let sent = transport.sent();
        assert_eq!(sent.len(), 50);
        assert!(sent.iter().all(|(path, _)| path == HEARTBEAT_PATH));
    }

    #[test]
    fn failures_back_off_never_stop_and_the_interval_resumes() {
        // A server down for 10 minutes of simulated time, then back.
        let intervals = intervals();
        let started = Instant::now();
        let mut hb = heartbeat(&intervals, started);
        let transport = FakeTransport::new(vec![]);
        let mut clock = Duration::ZERO;
        let mut attempts = 0;
        let (_, logs) = logs_of(|| {
            transport.push(ok(envelope(json!([]))));
            clock += hb.beat(&transport, None, started + clock, wall());
            while clock < secs(600) {
                transport.push(Err(ApiError::Transport("connection refused".into())));
                let wait = hb.beat(&transport, None, started + clock, wall());
                assert!(wait >= secs(2) && wait <= secs(300), "{wait:?}");
                clock += wait;
                attempts += 1;
            }
            transport.push(ok(envelope(json!([]))));
            let wait = hb.beat(&transport, None, started + clock, wall());
            assert!(wait >= secs(54) && wait <= secs(60), "{wait:?}");
        });
        assert!(
            (4..=12).contains(&attempts),
            "{attempts} attempts in 10 minutes"
        );
        assert!(logs.contains("first heartbeat accepted"), "{logs}");
        assert!(
            logs.contains("cannot reach the fleet server; will retry"),
            "{logs}"
        );
        assert!(
            logs.contains(&format!("failed_attempts={attempts}")),
            "{logs}"
        );
        assert!(
            logs.contains("heartbeats are being accepted again"),
            "{logs}"
        );
        // Uptime keeps counting across the outage.
        let last = transport.sent().last().unwrap().1.clone();
        assert_eq!(last["uptime_seconds"], clock.as_secs());
    }

    #[test]
    fn rate_limiting_waits_for_retry_after() {
        let intervals = intervals();
        let started = Instant::now();
        let mut hb = heartbeat(&intervals, started);
        let transport = FakeTransport::new(vec![Err(ApiError::RateLimited {
            retry_after: Some(secs(900)),
            request_id: None,
        })]);
        let (wait, _) = logs_of(|| hb.beat(&transport, None, started, wall()));
        assert!(wait >= secs(900) && wait <= secs(960), "{wait:?}");
    }

    #[test]
    fn server_intervals_are_applied_within_bounds() {
        let intervals = intervals();
        let started = Instant::now();
        let mut hb = heartbeat(&intervals, started);
        let transport = FakeTransport::new(vec![ok(envelope(json!({
            "intervals": {"heartbeat_seconds": 300, "inventory_seconds": 999_999}
        })))]);
        let (wait, logs) = logs_of(|| hb.beat(&transport, None, started, wall()));
        assert!(wait >= secs(270) && wait <= secs(300), "{wait:?}");
        assert_eq!(intervals.heartbeat(), secs(300));
        assert_eq!(intervals.inventory(), secs(21_600));
        assert!(logs.contains("interval set by the server"), "{logs}");
        assert!(
            logs.contains("outside this agent's configured bounds"),
            "{logs}"
        );
    }

    #[test]
    fn unknown_directives_are_ignored_and_logged_once() {
        let intervals = intervals();
        let started = Instant::now();
        let mut hb = heartbeat(&intervals, started);
        let body = envelope(json!({"collect_config": {"request_id": 1}, "reboot": true}));
        let transport = FakeTransport::new(vec![ok(body.clone()), ok(body)]);
        let (waits, logs) = logs_of(|| {
            [
                hb.beat(&transport, None, started, wall()),
                hb.beat(&transport, None, started, wall()),
            ]
        });
        assert!(waits.iter().all(|w| *w >= secs(54)), "{waits:?}");
        assert_eq!(
            logs.matches("ignored=\"directive `collect_config`\"")
                .count(),
            1,
            "{logs}"
        );
        assert_eq!(
            logs.matches("ignored=\"directive `reboot`\"").count(),
            1,
            "{logs}"
        );
        assert!(logs.contains("does not understand"), "{logs}");
        // Nothing else changed.
        assert_eq!(intervals.heartbeat(), secs(60));
    }

    #[test]
    fn a_malformed_envelope_still_counts_as_accepted() {
        let intervals = intervals();
        let started = Instant::now();
        let mut hb = heartbeat(&intervals, started);
        let transport = FakeTransport::new(vec![
            ok(json!(null)),
            ok(json!({"server_time": "yesterday", "directives": {"intervals": "fast"}})),
        ]);
        let (waits, logs) = logs_of(|| {
            [
                hb.beat(&transport, None, started, wall()),
                hb.beat(&transport, None, started, wall()),
            ]
        });
        assert!(
            waits.iter().all(|w| *w >= secs(54) && *w <= secs(60)),
            "{waits:?}"
        );
        assert!(logs.contains("the response is null"), "{logs}");
        assert!(logs.contains("directive `intervals` is a string"), "{logs}");
        assert!(
            logs.contains("server_time this agent cannot read"),
            "{logs}"
        );
        assert_eq!(intervals.heartbeat(), secs(60));
    }

    #[test]
    fn an_agent_update_directive_is_noted_not_acted_on() {
        let intervals = intervals();
        let started = Instant::now();
        let mut hb = heartbeat(&intervals, started);
        let body = envelope(json!({"agent_update": {
            "version": "0.2.0",
            "binary_url": "https://fleet-agent.example.lan/api/v1/releases/0.2.0/fleet-agent"
        }}));
        let transport = FakeTransport::new(vec![ok(body.clone()), ok(body)]);
        let (_, logs) = logs_of(|| {
            hb.beat(&transport, None, started, wall());
            hb.beat(&transport, None, started, wall());
        });
        assert_eq!(logs.matches("offered an agent update").count(), 1, "{logs}");
        assert!(logs.contains("offered_version=\"0.2.0\""), "{logs}");
        // Only heartbeats were sent: nothing was downloaded.
        assert!(
            transport
                .sent()
                .iter()
                .all(|(path, _)| path == HEARTBEAT_PATH)
        );
    }

    #[test]
    fn clock_skew_is_logged_when_it_starts_and_ends() {
        let intervals = intervals();
        let started = Instant::now();
        let mut hb = heartbeat(&intervals, started);
        let transport = FakeTransport::new(vec![]);
        let at_server = |offset: i64| {
            if offset >= 0 {
                wall() + secs(offset as u64)
            } else {
                wall() - secs(offset.unsigned_abs())
            }
        };
        let (_, logs) = logs_of(|| {
            for offset in [10, -400, -500, 30, 20] {
                transport.push(ok(envelope(json!([]))));
                hb.beat(&transport, None, started, at_server(offset));
            }
        });
        assert_eq!(
            logs.matches("clock differs from the server's").count(),
            1,
            "{logs}"
        );
        assert!(
            logs.contains("skew_seconds=400 agent_ahead=false"),
            "{logs}"
        );
        assert_eq!(
            logs.matches("agrees with the server's again").count(),
            1,
            "{logs}"
        );
    }
}
