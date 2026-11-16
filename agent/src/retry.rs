//! Retry policy for API calls (FR-1.2, P1-A02, ADR 0019).
//!
//! After a failure, [`Backoff::on_failure`] logs the failure plainly and returns how long to wait
//! before the next attempt; after a success, [`Backoff::on_success`] resets it. The agent never exits
//! because of a server-side failure; it waits and tries again.
//!
//! - Transient failures (unreachable server, TLS failure, timeouts, `5xx`, and other errors) use
//!   exponential backoff with "full jitter": the n-th consecutive failure waits a random time in
//!   `[floor, d]` where `d = min(base * 2^(n-1), cap)`. The wait never exceeds `cap` and never drops
//!   below `floor` (1 s), so there is no tight loop. Full jitter rather than "equal jitter" (`[d/2, d]`)
//!   spreads a fleet that failed together over the whole of `d`, so after an outage the agents come
//!   back over the 5 minutes of the cap, not the last 2.5 (P-16, #200).
//! - `401`, `403` (including `reenrollment_required`), and `426` cannot be fixed by retrying soon,
//!   so they wait a long interval (`long`, minus up to 10% jitter).
//! - A `429 rate_limited` with `Retry-After` is the server's own limit (per credential, failed
//!   authentication, release downloads, enrollment, onboarding: all a minute or less). Every loop waits
//!   at least that long plus a little jitter, and at least the normal backoff, but for at most
//!   [`RATE_LIMITED_MAX`] (15 minutes). A `429` with another code or none (a load balancer, proxy, or
//!   CDN in front of the server) is an ordinary transient failure, whatever its `Retry-After` says: a
//!   heartbeat that waited out a day would show the host offline, and an agent just updated would miss
//!   its confirmation deadline and roll back (#223).
//! - A `503 overloaded` with `Retry-After` is the server shedding report load (#200). Only the report
//!   loops honour it ([`RetryPolicy::reports`]), and for at most [`OVERLOADED_MAX`] (15 minutes): the
//!   server never sheds heartbeats, task calls, or update results, so for them, as for any other `503`
//!   (a load balancer or a maintenance page in front of the server), it is an ordinary transient
//!   failure. A heartbeat that waited out a day-long `Retry-After` would show the host offline, and an
//!   agent just updated would miss its confirmation deadline and roll back (review of #208).
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

    /// Seeded from the kernel's random source, so hosts cloned from one template and booted together
    /// (same process id, nearly the same clock) still spread out (review of #68). The clock and process
    /// id are only a fallback if `getrandom(2)` fails.
    pub fn from_entropy() -> Self {
        let mut bytes = [0u8; 8];
        let random = getrandom::getrandom(&mut bytes).map(|()| u64::from_ne_bytes(bytes));
        Self(entropy_seed(
            random.ok(),
            SystemTime::now(),
            std::process::id(),
        ))
    }
}

/// The seed: the kernel's random value when there is one, else the clock mixed with the process id.
fn entropy_seed(random: Option<u64>, now: SystemTime, pid: u32) -> u64 {
    random.unwrap_or_else(|| {
        let nanos = now
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        nanos ^ (u64::from(pid) << 32)
    })
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

/// The longest a report loop waits for a `503 overloaded` `Retry-After` (review of #208). The server
/// asks for at most 1.5 times `FLEET_REPORT_RETRY_AFTER_SECONDS`, which is at most 600: 900 seconds.
pub const OVERLOADED_MAX: Duration = Duration::from_secs(15 * 60);

/// The longest any loop waits for a `429 rate_limited` `Retry-After` (#223). The server's own limits
/// ask for at most a minute, so this only bounds a broken header; it is far below a day, so heartbeats
/// and update confirmations carry on.
pub const RATE_LIMITED_MAX: Duration = Duration::from_secs(15 * 60);

/// The retry timings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Upper bound of the first wait after a transient failure.
    pub base: Duration,
    /// Upper bound of any wait after a transient failure.
    pub cap: Duration,
    /// Lower bound of any wait after a transient failure, so full jitter never retries at once.
    pub floor: Duration,
    /// Wait after `401`, `403`, or `426`.
    pub long: Duration,
    /// The longest a `503 overloaded` `Retry-After` is honoured, or `None` to treat that `503` as
    /// transient. Only the report loops honour it ([`RetryPolicy::reports`]).
    pub overloaded_max: Option<Duration>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(5),
            cap: Duration::from_secs(5 * 60),
            floor: Duration::from_secs(1),
            long: Duration::from_secs(30 * 60),
            overloaded_max: None,
        }
    }
}

impl RetryPolicy {
    /// The report loops' policy: the default, and a `503 overloaded` with `Retry-After` waited out for
    /// up to [`OVERLOADED_MAX`] (#200, review of #208).
    pub fn reports() -> Self {
        Self {
            overloaded_max: Some(OVERLOADED_MAX),
            ..Self::default()
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
    /// How `error` is retried under `policy`: as [`RetryClass::of`], except that a `503 overloaded`
    /// with `Retry-After` is waited out, up to the policy's `overloaded_max`, when it has one.
    pub fn under(policy: &RetryPolicy, error: &ApiError) -> Self {
        match (policy.overloaded_max, error) {
            (
                Some(max),
                ApiError::Server {
                    status: 503,
                    code,
                    retry_after: Some(after),
                    ..
                },
            ) if code == "overloaded" => Self::After((*after).min(max)),
            _ => Self::of(error),
        }
    }

    /// How `error` is retried by a loop that does not honour load shedding: every `5xx` is transient.
    /// A `429 rate_limited` with `Retry-After` is waited out, for at most [`RATE_LIMITED_MAX`]; any
    /// other `429` is transient (#223).
    pub fn of(error: &ApiError) -> Self {
        match error {
            ApiError::Unauthorized { .. }
            | ApiError::ReenrollmentRequired { .. }
            | ApiError::Forbidden { .. }
            | ApiError::AgentVersionUnsupported { .. } => Self::Long,
            ApiError::RateLimited {
                code,
                retry_after: Some(after),
                ..
            } if code == "rate_limited" => Self::After((*after).min(RATE_LIMITED_MAX)),
            ApiError::RateLimited { .. }
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
        let class = RetryClass::under(&self.policy, error);
        let delay = self.next_delay(class);
        log_failure(error, delay, class);
        delay
    }

    /// The wait for the next failure of `class`, without logging.
    pub fn next_delay(&mut self, class: RetryClass) -> Duration {
        self.failures = self.failures.saturating_add(1);
        match class {
            Class::Transient => self.full_jitter(),
            Class::Long => {
                let long = self.policy.long;
                self.subtract_jitter(long, long / 10)
            }
            Class::After(after) => {
                let backoff = self.full_jitter();
                // Never earlier than the server asked, but spread above it (up to 10%, at most a
                // minute) so a fleet throttled together does not retry together (review of #65). The
                // classes that wait are already capped at 15 minutes (#221, #223); so is anything
                // else, so no loop can be held for longer.
                let after = after.min(OVERLOADED_MAX.max(RATE_LIMITED_MAX));
                let spread = (after / 10).clamp(Duration::from_secs(1), Duration::from_secs(60));
                self.add_jitter(after, spread).max(backoff)
            }
        }
    }

    /// A random wait in `[floor, min(base * 2^(failures - 1), cap)]` ("full jitter").
    fn full_jitter(&mut self) -> Duration {
        let ceiling = self.transient_ceiling();
        let floor = self.policy.floor.min(ceiling);
        self.subtract_jitter(ceiling, ceiling - floor)
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
fn log_failure(error: &ApiError, delay: Duration, class: RetryClass) {
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
        ApiError::RateLimited {
            code, retry_after, ..
        } if code == "rate_limited" => {
            tracing::warn!(
                status,
                code = "rate_limited",
                request_id,
                retry_after_seconds = retry_after.map(|d| d.as_secs()),
                retry_in_seconds,
                "the server is rate limiting this agent; waiting before retrying"
            )
        }
        ApiError::RateLimited {
            code, retry_after, ..
        } => tracing::warn!(
            status,
            code = code.as_str(),
            request_id,
            retry_after_seconds = retry_after.map(|d| d.as_secs()),
            retry_in_seconds,
            "too many requests (429), but not the fleet server's own rate limit (perhaps a proxy or load balancer in front of it); will retry"
        ),
        ApiError::PayloadTooLarge { .. } => tracing::error!(
            status,
            code = "payload_too_large",
            request_id,
            retry_in_seconds,
            "the server refused the request as too large"
        ),
        ApiError::Server {
            retry_after: Some(after),
            ..
        } if matches!(class, RetryClass::After(_)) => tracing::warn!(
            status,
            code = "overloaded",
            request_id,
            retry_after_seconds = after.as_secs(),
            retry_in_seconds,
            "the fleet server is busy and asked the agent to retry later; waiting before retrying"
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
            delays.iter().all(|d| *d >= policy.floor),
            "a wait was shorter than the floor"
        );
        // Once capped, waits fall anywhere in [floor, cap] ("full jitter", #200) and are not all equal.
        let capped = &delays[10..];
        let first = capped[0];
        assert!(capped.iter().any(|d| *d != first), "no jitter");
        assert!(
            capped.iter().any(|d| *d < policy.cap / 2),
            "full jitter reaches below half the cap"
        );
        // About one attempt every 150 s on average once capped: no tight loop.
        assert!(
            delays.len() < 24 * 3600 / 120,
            "{} attempts in a day",
            delays.len()
        );
        // Integer overflow cannot happen however long the outage lasts.
        b.failures = u32::MAX - 1;
        assert!(b.next_delay(Class::Transient) <= policy.cap);
        assert!(b.next_delay(Class::Transient) <= policy.cap);
    }

    #[test]
    fn full_jitter_stays_within_its_bounds_and_spreads_over_them() {
        // #200: the n-th failure waits uniformly in [floor, min(base * 2^(n-1), cap)], across a fleet.
        let policy = RetryPolicy::default();
        for failures in 1..=12u32 {
            let ceiling = policy
                .base
                .saturating_mul(1 << (failures - 1))
                .min(policy.cap);
            let delays: Vec<Duration> = (0..2_000u64)
                .map(|seed| {
                    let mut b = backoff(SplitMix64::new(seed));
                    b.failures = failures - 1;
                    b.next_delay(Class::Transient)
                })
                .collect();
            assert!(
                delays.iter().all(|d| *d >= policy.floor && *d <= ceiling),
                "failure {failures}: outside [{:?}, {ceiling:?}]",
                policy.floor
            );
            // Uniform: the mean is near the middle and both ends of the range are reached.
            let mean = delays.iter().sum::<Duration>() / delays.len() as u32;
            let middle = (policy.floor + ceiling) / 2;
            let slack = (ceiling - policy.floor) / 20;
            assert!(
                mean >= middle - slack && mean <= middle + slack,
                "failure {failures}: mean {mean:?}, middle {middle:?}"
            );
            let low = policy.floor + (ceiling - policy.floor) / 10;
            let high = ceiling - (ceiling - policy.floor) / 10;
            assert!(delays.iter().any(|d| *d <= low), "failure {failures}");
            assert!(delays.iter().any(|d| *d >= high), "failure {failures}");
        }
    }

    #[test]
    fn a_fleet_back_from_an_outage_spreads_over_the_whole_cap() {
        // #200: agents that have all reached the cap come back spread over [floor, cap], not crowded
        // into its second half as with equal jitter: no 30 s window holds much more than its share.
        let policy = RetryPolicy::default();
        let mut buckets = [0u32; 10];
        for seed in 0..10_000u64 {
            let mut b = backoff(SplitMix64::new(seed));
            b.failures = 20;
            let d = b.next_delay(Class::Transient);
            buckets[((d.as_millis() * 10 / (policy.cap.as_millis() + 1)) as usize).min(9)] += 1;
        }
        assert!(
            buckets.iter().all(|n| (800..=1_200).contains(n)),
            "{buckets:?}"
        );
    }

    #[test]
    fn only_the_report_loops_honour_a_503_overloaded_and_for_at_most_15_minutes() {
        // #200, review of #208: the server sheds report load with 503 overloaded and Retry-After.
        let shed = |after: u64, code: &str| ApiError::Server {
            status: 503,
            code: code.into(),
            retry_after: Some(secs(after)),
            request_id: None,
        };
        let reports = RetryPolicy::reports();
        let others = RetryPolicy::default();
        assert_eq!(reports.overloaded_max, Some(OVERLOADED_MAX));
        assert_eq!(others.overloaded_max, None);
        assert_eq!(
            RetryClass::under(&reports, &shed(60, "overloaded")),
            Class::After(secs(60))
        );
        // Capped at 15 minutes, not the day a broken header could ask for.
        assert_eq!(
            RetryClass::under(&reports, &shed(86_400, "overloaded")),
            Class::After(OVERLOADED_MAX)
        );
        // Heartbeats, task calls, and update results: transient, whatever the header says.
        assert_eq!(
            RetryClass::under(&others, &shed(86_400, "overloaded")),
            Class::Transient
        );
        // A 503 that is not the server's shedding (a proxy page, another code), or another 5xx.
        assert_eq!(RetryClass::under(&reports, &shed(60, "")), Class::Transient);
        assert_eq!(
            RetryClass::under(&reports, &shed(60, "internal_error")),
            Class::Transient
        );
        let other_5xx = ApiError::Server {
            status: 500,
            code: "overloaded".into(),
            retry_after: Some(secs(60)),
            request_id: None,
        };
        assert_eq!(RetryClass::under(&reports, &other_5xx), Class::Transient);

        // In the report loops: at least Retry-After, spread above it, so a fleet does not come back
        // together; and logged as the server being busy.
        let delays: Vec<Duration> = (0..200)
            .map(|seed| {
                logs_of(|| {
                    Backoff::new(reports, SplitMix64::new(seed)).on_failure(&shed(60, "overloaded"))
                })
                .0
            })
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
        let (long, logs) = logs_of(|| {
            Backoff::new(reports, SplitMix64::new(1)).on_failure(&shed(86_400, "overloaded"))
        });
        assert!(long <= OVERLOADED_MAX + secs(60), "{long:?}");
        assert!(
            logs.contains("busy and asked the agent to retry later"),
            "{logs}"
        );

        // In the heartbeat loop the first retry is the normal backoff, at most 5 s, and is logged as a
        // server error, not as a wait the agent does not do.
        let (beat, logs) = logs_of(|| {
            Backoff::new(others, SplitMix64::new(1)).on_failure(&shed(86_400, "overloaded"))
        });
        assert!(beat <= secs(5), "{beat:?}");
        assert!(logs.contains("had an internal error; will retry"), "{logs}");
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
        use crate::test_support::{TempDir, TestPki, TlsServer, http_reply};

        let reply = http_reply("401 Unauthorized", &[], "");
        let pki = TestPki::generate();
        let dir = TempDir::new();
        let server = TlsServer::start(&pki, vec![reply; 3]);
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
        // Delays up to 15 minutes are honoured in full; nothing waits longer (#221, #223).
        assert_eq!(b.next_delay(Class::After(secs(900))), secs(900));
        assert_eq!(b.next_delay(Class::After(secs(7200))), secs(900));
        assert_eq!(b.next_delay(Class::After(secs(86_400 * 30))), secs(900));
    }

    fn limited(code: &str, after: Option<u64>) -> ApiError {
        ApiError::RateLimited {
            code: code.into(),
            retry_after: after.map(secs),
            request_id: None,
        }
    }

    #[test]
    fn only_a_429_rate_limited_retry_after_is_honoured_and_for_at_most_15_minutes() {
        // #223: the server's own 429s ask for a minute or less; a 429 from a proxy, load balancer, or
        // CDN in front of it must not hold any loop for a day. The same under every loop's policy.
        for policy in [RetryPolicy::default(), RetryPolicy::reports()] {
            let class = |error: &ApiError| RetryClass::under(&policy, error);
            assert_eq!(
                class(&limited("rate_limited", Some(9))),
                Class::After(secs(9))
            );
            assert_eq!(
                class(&limited("rate_limited", Some(60))),
                Class::After(secs(60))
            );
            assert_eq!(
                class(&limited("rate_limited", Some(86_400))),
                Class::After(RATE_LIMITED_MAX)
            );
            // No header, another code, or no envelope at all: transient, whatever the header says.
            assert_eq!(class(&limited("rate_limited", None)), Class::Transient);
            assert_eq!(class(&limited("", Some(86_400))), Class::Transient);
            assert_eq!(class(&limited("", Some(9))), Class::Transient);
            assert_eq!(class(&limited("slow_down", Some(60))), Class::Transient);
            assert_eq!(class(&limited("Rate_Limited", Some(60))), Class::Transient);

            // A day-long header waits at most 15 minutes plus the spread (a minute), and no less
            // than 15 minutes.
            for seed in 0..50 {
                let (wait, logs) = logs_of(|| {
                    Backoff::new(policy, SplitMix64::new(seed))
                        .on_failure(&limited("rate_limited", Some(86_400)))
                });
                assert!(
                    wait >= RATE_LIMITED_MAX && wait <= RATE_LIMITED_MAX + secs(60),
                    "{wait:?}"
                );
                assert!(
                    logs.contains("the server is rate limiting this agent"),
                    "{logs}"
                );
            }
            // The server's own short window: at least what it asked, spread a little above it.
            let short = logs_of(|| {
                Backoff::new(policy, SplitMix64::new(4))
                    .on_failure(&limited("rate_limited", Some(60)))
            })
            .0;
            assert!(short >= secs(60) && short <= secs(66), "{short:?}");

            // A proxy's 429: the normal backoff, at most 5 s on the first failure and 5 minutes ever,
            // and logged as not the server's limit.
            let mut b = Backoff::new(policy, SplitMix64::new(2));
            let (first, logs) = logs_of(|| b.on_failure(&limited("", Some(86_400))));
            assert!(first <= secs(5), "{first:?}");
            assert!(
                logs.contains("not the fleet server's own rate limit"),
                "{logs}"
            );
            assert!(logs.contains("retry_after_seconds=86400"), "{logs}");
            for _ in 0..20 {
                let wait = logs_of(|| b.on_failure(&limited("", Some(86_400)))).0;
                assert!(wait <= policy.cap, "{wait:?}");
            }
        }
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
        // The spread is at most a minute even for the longest delay.
        let long = backoff(SplitMix64::new(3)).next_delay(Class::After(secs(900)));
        assert!(long >= secs(900) && long <= secs(960), "{long:?}");
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
            limited("rate_limited", Some(30)),
            limited("", Some(30)),
            ApiError::PayloadTooLarge { request_id: None },
            ApiError::Server {
                status: 503,
                code: String::new(),
                retry_after: None,
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

    #[test]
    fn jitter_seeds_come_from_the_kernel_not_the_clock_and_pid() {
        // Review of #68: two hosts with the same pid and clock must still get different seeds.
        let now = UNIX_EPOCH + Duration::from_secs(1_767_268_800);
        assert_eq!(entropy_seed(Some(7), now, 1234), 7);
        assert_eq!(entropy_seed(Some(8), now, 1234), 8);
        assert_eq!(
            entropy_seed(None, now, 1234),
            1_767_268_800_000_000_000 ^ (1234u64 << 32)
        );
        let seeds: std::collections::HashSet<u64> =
            (0..100).map(|_| SplitMix64::from_entropy().0).collect();
        assert_eq!(seeds.len(), 100);
    }
}
