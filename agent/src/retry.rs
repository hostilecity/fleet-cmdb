//! Retry policy for API calls (FR-1.2, P1-A02, ADR 0019).
//!
//! After a failure, [`Backoff::on_failure`] logs the failure plainly and returns how long to wait
//! before the next attempt; after a success, [`Backoff::on_success`] resets it. The agent never exits
//! because of a server-side failure; it waits and tries again.
//!
//! - Transient failures (unreachable server, TLS failure, timeouts, `5xx`, and other errors) use
//!   exponential backoff with "equal jitter": the n-th consecutive failure waits a random time in
//!   `[d/2, d]` where `d = min(base * 2^(n-1), cap)`. The wait never exceeds `cap` and never drops
//!   below `base / 2`, so there is no tight loop.
//! - `401`, `403` (including `reenrollment_required`), and `426` cannot be fixed by retrying soon,
//!   so they wait a long interval (`long`, minus up to 10% jitter).
//! - `429` waits at least the server's `Retry-After` plus a little jitter (only a broken header over a day is capped), and at least the
//!   normal backoff.
//!
//! Randomness comes from an injected [`Rng`], so tests are deterministic.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::AGENT_VERSION;
use crate::client::ApiError;

/// A source of random numbers for jitter. Not used for anything secret.
pub trait Rng {
    fn next_u64(&mut self) -> u64;
}

/// SplitMix64: a small, fast generator, plenty for spreading retries across a fleet.
#[derive(Debug, Clone)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Seeded from the clock and process id, so hosts restarted together still spread out.
    pub fn from_entropy() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        Self(nanos ^ (u64::from(std::process::id()) << 32))
    }
}

impl Rng for SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// The retry timings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Upper bound of the first wait after a transient failure.
    pub base: Duration,
    /// Upper bound of any wait after a transient failure.
    pub cap: Duration,
    /// Wait after `401`, `403`, or `426`.
    pub long: Duration,
    /// A safety ceiling on `Retry-After`, only against a broken header (a server bug sending years
    /// would otherwise silence the fleet until restarted). Any realistic load-shedding delay is honoured
    /// in full (ADR 0019, review of #65).
    pub retry_after_max: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(5),
            cap: Duration::from_secs(5 * 60),
            long: Duration::from_secs(30 * 60),
            retry_after_max: Duration::from_secs(24 * 60 * 60),
        }
    }
}

/// How a failure is retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryClass {
    /// Exponential backoff with jitter.
    Transient,
    /// Needs an operator or an upgrade; wait the long interval.
    Long,
    /// Wait at least this long, as the server asked.
    After(Duration),
}

impl RetryClass {
    pub fn of(error: &ApiError) -> Self {
        match error {
            ApiError::Unauthorized { .. }
            | ApiError::ReenrollmentRequired { .. }
            | ApiError::Forbidden { .. }
            | ApiError::AgentVersionUnsupported { .. } => Self::Long,
            ApiError::RateLimited {
                retry_after: Some(after),
                ..
            } => Self::After(*after),
            ApiError::RateLimited {
                retry_after: None, ..
            }
            | ApiError::Transport(_)
            | ApiError::Server { .. }
            | ApiError::PayloadTooLarge { .. }
            | ApiError::Rejected { .. }
            | ApiError::InvalidResponse(_) => Self::Transient,
        }
    }
}

/// Consecutive-failure state for one kind of request (for example heartbeats).
#[derive(Debug, Clone)]
pub struct Backoff<R: Rng> {
    policy: RetryPolicy,
    failures: u32,
    rng: R,
}

impl<R: Rng> Backoff<R> {
    pub fn new(policy: RetryPolicy, rng: R) -> Self {
        Self {
            policy,
            failures: 0,
            rng,
        }
    }

    /// Consecutive failures since the last success.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Call after a successful request: the next failure starts again from `base`.
    pub fn on_success(&mut self) {
        self.failures = 0;
    }

    /// Call after a failed request: logs it plainly and returns how long to wait before retrying.
    pub fn on_failure(&mut self, error: &ApiError) -> Duration {
        let delay = self.next_delay(RetryClass::of(error));
        log_failure(error, delay);
        delay
    }

    /// The wait for the next failure of `class`, without logging.
    pub fn next_delay(&mut self, class: RetryClass) -> Duration {
        self.failures = self.failures.saturating_add(1);
        match class {
            Class::Transient => {
                let ceiling = self.transient_ceiling();
                self.subtract_jitter(ceiling, ceiling / 2)
            }
            Class::Long => {
                let long = self.policy.long;
                self.subtract_jitter(long, long / 10)
            }
            Class::After(after) => {
                let ceiling = self.transient_ceiling();
                let backoff = self.subtract_jitter(ceiling, ceiling / 2);
                // Never earlier than the server asked, but spread above it (up to 10%, at most a
                // minute) so a fleet throttled together does not retry together (review of #65).
                let after = after.min(self.policy.retry_after_max);
                let spread = (after / 10).clamp(Duration::from_secs(1), Duration::from_secs(60));
                self.add_jitter(after, spread).max(backoff)
            }
        }
    }

    /// `min(base * 2^(failures - 1), cap)`.
    fn transient_ceiling(&self) -> Duration {
        let exponent = self.failures.saturating_sub(1).min(31);
        self.policy
            .base
            .saturating_mul(1 << exponent)
            .min(self.policy.cap)
    }

    /// `value` plus a random amount in `[0, spread]`.
    fn add_jitter(&mut self, value: Duration, spread: Duration) -> Duration {
        let spread_ms = spread.as_millis() as u64;
        value + Duration::from_millis(self.rng.next_u64() % (spread_ms + 1))
    }

    /// `value` minus a random amount in `[0, spread]`.
    fn subtract_jitter(&mut self, value: Duration, spread: Duration) -> Duration {
        let spread_ms = spread.as_millis() as u64;
        if spread_ms == 0 {
            return value;
        }
        value - Duration::from_millis(self.rng.next_u64() % (spread_ms + 1))
    }
}

use RetryClass as Class;

/// One plain log line per failure, saying what happened and what the operator can do.
fn log_failure(error: &ApiError, delay: Duration) {
    let status = error.status();
    let request_id = error.request_id().unwrap_or("");
    let retry_in_seconds = delay.as_secs();
    match error {
        ApiError::Transport(reason) => tracing::warn!(
            status,
            retry_in_seconds,
            reason = reason.as_str(),
            "cannot reach the fleet server; will retry"
        ),
        ApiError::Unauthorized { .. } => tracing::error!(
            status,
            code = "unauthorized",
            request_id,
            retry_in_seconds,
            "the server rejected this agent's credential (it may have been revoked, or the host retired); \
             re-enrol with `fleet-agent install --reenroll`, or `fleet-agent install --token` with a new enrollment token"
        ),
        ApiError::ReenrollmentRequired { .. } => tracing::error!(
            status,
            code = "reenrollment_required",
            request_id,
            retry_in_seconds,
            "this host is waiting to be re-enrolled; run `fleet-agent install --reenroll`, \
             or `fleet-agent install --token` with the new token"
        ),
        ApiError::Forbidden { code, .. } => tracing::error!(
            status,
            code = code.as_str(),
            request_id,
            retry_in_seconds,
            "the server refused this host; check its state in the dashboard"
        ),
        ApiError::AgentVersionUnsupported { message, .. } => tracing::error!(
            status,
            code = "agent_version_unsupported",
            agent_version = AGENT_VERSION,
            request_id,
            retry_in_seconds,
            server_message = message.as_str(),
            "the server no longer supports this agent version; upgrade fleet-agent. The agent keeps running and will retry"
        ),
        ApiError::RateLimited { retry_after, .. } => tracing::warn!(
            status,
            code = "rate_limited",
            request_id,
            retry_after_seconds = retry_after.map(|d| d.as_secs()),
            retry_in_seconds,
            "the server is rate limiting this agent; waiting before retrying"
        ),
        ApiError::PayloadTooLarge { .. } => tracing::error!(
            status,
            code = "payload_too_large",
            request_id,
            retry_in_seconds,
            "the server refused the request as too large"
        ),
        ApiError::Server { .. } => tracing::warn!(
            status,
            request_id,
            retry_in_seconds,
            "the fleet server had an internal error; will retry"
        ),
        ApiError::Rejected { code, message, .. } => tracing::error!(
            status,
            code = code.as_str(),
            request_id,
            retry_in_seconds,
            server_message = message.as_str(),
            "the server rejected the request"
        ),
        ApiError::InvalidResponse(reason) => tracing::warn!(
            retry_in_seconds,
            reason = reason.as_str(),
            "the server sent a response the agent cannot read; will retry"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::capture::logs_of;

    /// A scripted "random" source.
    struct Fixed(Vec<u64>, usize);

    impl Rng for Fixed {
        fn next_u64(&mut self) -> u64 {
            let v = self.0[self.1 % self.0.len()];
            self.1 += 1;
            v
        }
    }

    fn backoff(rng: impl Rng) -> Backoff<impl Rng> {
        Backoff::new(RetryPolicy::default(), rng)
    }

    fn transient() -> ApiError {
        ApiError::Transport("connection refused".into())
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn backoff_doubles_up_to_the_cap_without_jitter() {
        // Jitter of 0 shows the ceilings: 5, 10, 20, ... capped at 300.
        let mut b = backoff(Fixed(vec![0], 0));
        let delays: Vec<u64> = (0..10)
            .map(|_| b.next_delay(Class::Transient).as_secs())
            .collect();
        assert_eq!(delays, [5, 10, 20, 40, 80, 160, 300, 300, 300, 300]);
    }

    #[test]
    fn backoff_is_capped_and_jittered_over_a_long_outage() {
        // A fake clock: add each wait and check the sequence over a simulated day-long outage.
        let mut b = backoff(SplitMix64::new(42));
        let mut clock = Duration::ZERO;
        let mut delays = Vec::new();
        while clock < secs(24 * 3600) {
            let d = b.next_delay(Class::Transient);
            clock += d;
            delays.push(d);
        }
        let policy = RetryPolicy::default();
        assert!(
            delays.iter().all(|d| *d <= policy.cap),
            "a wait exceeded the cap"
        );
        assert!(
            delays.iter().all(|d| *d >= policy.base / 2),
            "a wait was too short"
        );
        // Once capped, waits fall in [cap/2, cap] and are not all equal: jitter is applied.
        let capped = &delays[10..];
        assert!(capped.iter().all(|d| *d >= policy.cap / 2));
        let first = capped[0];
        assert!(capped.iter().any(|d| *d != first), "no jitter");
        // About one attempt every 225 s on average once capped: no tight loop.
        assert!(
            delays.len() < 24 * 3600 / 150,
            "{} attempts in a day",
            delays.len()
        );
        // Integer overflow cannot happen however long the outage lasts.
        b.failures = u32::MAX - 1;
        assert!(b.next_delay(Class::Transient) <= policy.cap);
        assert!(b.next_delay(Class::Transient) <= policy.cap);
    }

    #[test]
    fn jitter_differs_between_hosts() {
        let mut a = backoff(SplitMix64::new(1));
        let mut b = backoff(SplitMix64::new(2));
        let a: Vec<_> = (0..8).map(|_| a.next_delay(Class::Transient)).collect();
        let b: Vec<_> = (0..8).map(|_| b.next_delay(Class::Transient)).collect();
        assert_ne!(a, b);
    }

    #[test]
    fn success_resets_the_backoff() {
        let mut b = backoff(Fixed(vec![0], 0));
        for _ in 0..6 {
            b.next_delay(Class::Transient);
        }
        assert_eq!(b.next_delay(Class::Transient), secs(300));
        b.on_success();
        assert_eq!(b.failures(), 0);
        assert_eq!(b.next_delay(Class::Transient), secs(5));
        assert_eq!(b.next_delay(Class::Transient), secs(10));
    }

    #[test]
    fn auth_reenrollment_and_version_errors_wait_the_long_interval() {
        let long = RetryPolicy::default().long;
        for error in [
            ApiError::Unauthorized { request_id: None },
            ApiError::ReenrollmentRequired { request_id: None },
            ApiError::Forbidden {
                code: "host_not_active".into(),
                request_id: None,
            },
            ApiError::AgentVersionUnsupported {
                message: String::new(),
                request_id: None,
            },
        ] {
            let mut b = backoff(SplitMix64::new(7));
            // Even straight after a success, and on every repeat, the wait stays long.
            for _ in 0..20 {
                let d = logs_of(|| b.on_failure(&error)).0;
                assert!(d >= long - long / 10 && d <= long, "{error:?}: {d:?}");
            }
        }
    }

    #[test]
    fn a_401_never_causes_a_tight_loop() {
        // Fake clock over a simulated day of constant 401s: at most one attempt per 27 minutes.
        let mut b = backoff(SplitMix64::new(9));
        let mut clock = Duration::ZERO;
        let mut attempts = 0;
        while clock < secs(24 * 3600) {
            attempts += 1;
            clock += logs_of(|| b.on_failure(&ApiError::Unauthorized { request_id: None })).0;
        }
        assert!(attempts <= 24 * 60 / 27 + 1, "{attempts} attempts in a day");
    }

    #[test]
    fn a_401_from_a_real_server_backs_off_long() {
        use crate::client::tests::trusting_client;
        use crate::test_support::{TempDir, TestPki, TlsServer};

        let reply = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let pki = TestPki::generate();
        let dir = TempDir::new();
        let server = TlsServer::start(&pki, vec![reply.to_owned(); 3]);
        let client = trusting_client(&server, &pki, &dir);
        let mut b = backoff(SplitMix64::new(11));
        let mut clock = Duration::ZERO;
        for _ in 0..3 {
            let error = client
                .post_json("/api/v1/heartbeat", &serde_json::json!({}))
                .unwrap_err();
            let (delay, logs) = logs_of(|| b.on_failure(&error));
            assert!(logs.contains("rejected this agent's credential"), "{logs}");
            assert!(delay >= secs(27 * 60), "{delay:?}");
            clock += delay;
        }
        assert_eq!(server.finish().len(), 3);
        assert!(clock >= secs(3 * 27 * 60));
    }

    #[test]
    fn retry_after_is_honoured_and_bounded() {
        let mut b = backoff(Fixed(vec![0], 0));
        assert_eq!(b.next_delay(Class::After(secs(120))), secs(120));
        // Never shorter than the normal backoff for this failure count.
        for _ in 0..8 {
            b.next_delay(Class::Transient);
        }
        assert_eq!(b.next_delay(Class::After(secs(1))), secs(300));
        // Long load-shedding delays are honoured in full (ADR 0019, review of #65).
        assert_eq!(b.next_delay(Class::After(secs(7200))), secs(7200));
        assert_eq!(b.next_delay(Class::After(secs(20 * 3600))), secs(20 * 3600));
        // Only a broken header beyond a day is limited.
        assert_eq!(b.next_delay(Class::After(secs(86_400 * 30))), secs(86_400));
        assert_eq!(
            RetryClass::of(&ApiError::RateLimited {
                retry_after: Some(secs(9)),
                request_id: None
            }),
            Class::After(secs(9))
        );
        assert_eq!(
            RetryClass::of(&ApiError::RateLimited {
                retry_after: None,
                request_id: None
            }),
            Class::Transient
        );
    }

    #[test]
    fn retry_after_is_spread_above_the_servers_delay_never_below() {
        // A fleet throttled together must not retry together (review of #65).
        let delays: Vec<Duration> = (0..200)
            .map(|seed| backoff(SplitMix64::new(seed)).next_delay(Class::After(secs(60))))
            .collect();
        assert!(
            delays.iter().all(|d| *d >= secs(60) && *d <= secs(66)),
            "{delays:?}"
        );
        let distinct: std::collections::BTreeSet<_> = delays.iter().collect();
        assert!(
            distinct.len() > 100,
            "only {} distinct delays",
            distinct.len()
        );
        // The spread is at most a minute even for long delays.
        let long = backoff(SplitMix64::new(3)).next_delay(Class::After(secs(7200)));
        assert!(long >= secs(7200) && long <= secs(7260), "{long:?}");
    }

    #[test]
    fn a_426_is_logged_plainly_and_the_agent_keeps_going() {
        let error = ApiError::AgentVersionUnsupported {
            message: "minimum agent version is 9.0.0".into(),
            request_id: Some("req-426".into()),
        };
        let mut b = backoff(SplitMix64::new(3));
        let (delay, logs) = logs_of(|| b.on_failure(&error));
        assert!(delay >= secs(27 * 60));
        assert!(logs.contains("ERROR"), "{logs}");
        assert!(
            logs.contains("no longer supports this agent version"),
            "{logs}"
        );
        assert!(logs.contains("upgrade fleet-agent"), "{logs}");
        assert!(
            logs.contains("code=\"agent_version_unsupported\""),
            "{logs}"
        );
        assert!(
            logs.contains(&format!("agent_version=\"{AGENT_VERSION}\"")),
            "{logs}"
        );
        assert!(logs.contains("minimum agent version is 9.0.0"), "{logs}");
        assert!(logs.contains("request_id=\"req-426\""), "{logs}");
    }

    #[test]
    fn reenrollment_log_says_what_to_run() {
        let mut b = backoff(SplitMix64::new(3));
        let (_, logs) =
            logs_of(|| b.on_failure(&ApiError::ReenrollmentRequired { request_id: None }));
        assert!(logs.contains("fleet-agent install --reenroll"), "{logs}");
        assert!(logs.contains("fleet-agent install --token"), "{logs}");
    }

    #[test]
    fn every_failure_kind_logs_one_line() {
        let errors = [
            transient(),
            ApiError::Unauthorized { request_id: None },
            ApiError::RateLimited {
                retry_after: Some(secs(30)),
                request_id: None,
            },
            ApiError::PayloadTooLarge { request_id: None },
            ApiError::Server {
                status: 503,
                request_id: None,
            },
            ApiError::Rejected {
                status: 400,
                code: "validation_failed".into(),
                message: "bad".into(),
                request_id: None,
            },
            ApiError::InvalidResponse("not json".into()),
        ];
        let mut b = backoff(SplitMix64::new(5));
        for error in errors {
            let (_, logs) = logs_of(|| b.on_failure(&error));
            assert_eq!(logs.lines().count(), 1, "{logs}");
            assert!(logs.contains("retry_in_seconds="), "{logs}");
        }
    }
}
