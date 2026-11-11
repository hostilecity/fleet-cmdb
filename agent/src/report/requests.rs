//! On-demand report requests (DEC-13, P2-S03, P2-A01): the `report_request` heartbeat directive
//! becomes at most one extra report per type.
//!
//! The server puts `{"report_request": {"types": [...]}}` in the heartbeat response on **every**
//! heartbeat until it has accepted a report of each requested type that was collected after the
//! request reached the agent, or the request expires after an hour. The agent must therefore not send
//! a report per heartbeat: it sends **one** per *episode*, an episode being a run of accepted
//! heartbeats that carry the type. The first heartbeat of an episode raises a pending request
//! ([`ReportRequests::observe`]); the report loop takes it ([`ReportRequests::take`]), collects after
//! that moment, and sends. Later heartbeats of the same episode raise nothing. A heartbeat response
//! without the type ends its episode, so a new operator request, later, starts a new one. A heartbeat
//! that fails says nothing and changes nothing, and neither does one whose `report_request` (or whole
//! `directives`) is present but unreadable: it is not observed at all, since reading it as "no types"
//! would end the episode and the next readable heartbeat would raise the same request again.
//!
//! An episode also ends when the server has accepted the report sent for it
//! ([`ReportRequests::answered`]): the server stops listing a type once such a report is in, so a
//! heartbeat *sent after* that acceptance that still lists the type carries a new request (an operator
//! may ask again after five minutes, sooner than a long heartbeat interval brings a heartbeat without
//! the type; review of #114). A heartbeat sent before the acceptance proves nothing, since the server
//! may have built its answer before the report arrived, so it raises nothing. The directive carries no
//! request identifier, so this ordering is how one request is told from the next.
//!
//! If the report is lost or rejected, the episode still gives no second report: the next scheduled
//! report follows its normal timetable, and the server expires the request. That is the "one extra
//! report and then no more" of P2-A01, at the cost of an hour of "requested" on the dashboard in the
//! failure case.
//!
//! A type the agent has no report for is not listed here: the heartbeat logs it once as ignored, and
//! the server's own timetable satisfies it.

use std::sync::{Mutex, PoisonError};
use std::time::Instant;

/// The report types an operator can ask for that this agent sends on request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportType {
    Config,
    Inventory,
    Packages,
}

impl ReportType {
    pub const ALL: [ReportType; 3] = [
        ReportType::Config,
        ReportType::Inventory,
        ReportType::Packages,
    ];

    /// The type's name in `directives.report_request.types`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Inventory => "inventory",
            Self::Packages => "packages",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.name() == name)
    }

    fn index(self) -> usize {
        match self {
            Self::Config => 0,
            Self::Inventory => 1,
            Self::Packages => 2,
        }
    }
}

#[derive(Default)]
struct Inner {
    /// The type is in the heartbeat responses of the current episode.
    present: [bool; 3],
    /// When the episode's request was raised, until a report loop takes it.
    pending: [Option<Instant>; 3],
    /// When the report sent for the episode was accepted.
    answered: [Option<Instant>; 3],
}

/// Shared between the heartbeat loop, which observes, and the report loops, which take.
#[derive(Default)]
pub struct ReportRequests(Mutex<Inner>);

impl ReportRequests {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records what one accepted heartbeat response asked for (`wanted` empty when it had no
    /// `report_request`); `sent` is when that heartbeat was sent. Returns the types whose episode
    /// just began.
    pub fn observe(&self, wanted: &[ReportType], sent: Instant) -> Vec<ReportType> {
        let mut inner = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let mut began = Vec::new();
        for ty in ReportType::ALL {
            let i = ty.index();
            if wanted.contains(&ty) {
                let new_request = inner.answered[i].is_some_and(|answered| answered < sent);
                if !inner.present[i] || new_request {
                    inner.present[i] = true;
                    inner.pending[i] = Some(sent);
                    inner.answered[i] = None;
                    began.push(ty);
                }
            } else {
                inner.present[i] = false;
                inner.answered[i] = None;
            }
        }
        began
    }

    /// The server accepted the report sent for `ty`'s current request, at `at` or before.
    pub fn answered(&self, ty: ReportType, at: Instant) {
        let mut inner = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if inner.present[ty.index()] {
            inner.answered[ty.index()] = Some(at);
        }
    }

    /// A request from the agent itself, not the server: a task that changed the packages
    /// (`apply_package_updates`, P3-AGENT-UPDATES) asks for one report of `ty` now. It starts no
    /// episode, so the server's own requests are read as before; one already pending is kept.
    pub fn raise(&self, ty: ReportType, at: Instant) {
        let mut inner = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        inner.pending[ty.index()].get_or_insert(at);
    }

    /// Takes the pending request of `ty`, if any: when it was raised.
    pub fn take(&self, ty: ReportType) -> Option<Instant> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pending[ty.index()]
        .take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ReportType::{Config, Inventory, Packages};
    use std::time::Duration;

    #[test]
    fn a_directive_causes_one_request_however_many_heartbeats_carry_it() {
        let requests = ReportRequests::new();
        let now = Instant::now();
        assert_eq!(requests.observe(&[Config], now), [Config]);
        assert_eq!(requests.take(Config), Some(now));
        // The same directive on every later heartbeat raises nothing, taken or not.
        for _ in 0..5 {
            assert!(requests.observe(&[Config], now).is_empty());
            assert_eq!(requests.take(Config), None);
        }
    }

    #[test]
    fn the_agent_can_ask_for_a_report_without_starting_an_episode() {
        // apply_package_updates (P3-AGENT-UPDATES) asks for a package report after an upgrade.
        let requests = ReportRequests::new();
        let first = Instant::now();
        requests.raise(Packages, first);
        requests.raise(Packages, first + Duration::from_secs(1));
        assert_eq!(requests.take(Packages), Some(first));
        assert_eq!(requests.take(Packages), None);
        assert_eq!(requests.take(Config), None);
        // A server request that arrives later still starts its own episode.
        assert_eq!(requests.observe(&[Packages], Instant::now()), [Packages]);
        assert!(requests.take(Packages).is_some());
    }

    #[test]
    fn a_request_not_yet_taken_is_not_raised_again() {
        let requests = ReportRequests::new();
        let first = Instant::now();
        requests.observe(&[Config], first);
        assert!(requests.observe(&[Config], Instant::now()).is_empty());
        assert_eq!(requests.take(Config), Some(first));
    }

    #[test]
    fn the_directive_going_away_ends_the_episode_and_a_new_one_starts_a_new_request() {
        let requests = ReportRequests::new();
        requests.observe(&[Config], Instant::now());
        requests.take(Config);
        assert!(requests.observe(&[], Instant::now()).is_empty());
        assert_eq!(requests.observe(&[Config], Instant::now()), [Config]);
        assert!(requests.take(Config).is_some());
    }

    #[test]
    fn a_new_request_after_the_answer_was_accepted_starts_a_new_episode() {
        // Review of #114: report accepted, operator asks again after the five-minute cooldown, and the
        // next heartbeat (ten minutes on) lists the type again with no heartbeat without it between.
        let requests = ReportRequests::new();
        let t0 = Instant::now();
        assert_eq!(requests.observe(&[Config], t0), [Config]);
        assert!(requests.take(Config).is_some());
        requests.answered(Config, t0 + Duration::from_secs(5));
        let next = t0 + Duration::from_secs(600);
        assert_eq!(requests.observe(&[Config], next), [Config]);
        assert_eq!(requests.take(Config), Some(next));
        // And that one is again raised only once.
        assert!(
            requests
                .observe(&[Config], next + Duration::from_secs(60))
                .is_empty()
        );
    }

    #[test]
    fn a_heartbeat_sent_before_the_answer_was_accepted_raises_nothing() {
        // The server may have built that response before the report arrived.
        let requests = ReportRequests::new();
        let t0 = Instant::now();
        requests.observe(&[Config], t0);
        requests.take(Config);
        let in_flight = t0 + Duration::from_secs(60);
        requests.answered(Config, t0 + Duration::from_secs(61));
        assert!(requests.observe(&[Config], in_flight).is_empty());
        assert_eq!(requests.take(Config), None);
    }

    #[test]
    fn an_unanswered_request_is_still_one_report() {
        // A lost or rejected report is not answered, so the repeated directive raises nothing.
        let requests = ReportRequests::new();
        let t0 = Instant::now();
        requests.observe(&[Config], t0);
        requests.take(Config);
        for i in 1..10 {
            assert!(
                requests
                    .observe(&[Config], t0 + Duration::from_secs(i * 60))
                    .is_empty()
            );
        }
    }

    #[test]
    fn types_are_independent() {
        let requests = ReportRequests::new();
        assert_eq!(
            requests.observe(&[Config, Inventory], Instant::now()),
            [Config, Inventory]
        );
        assert!(requests.take(Inventory).is_some());
        // Config's episode goes on; inventory's ended.
        assert!(requests.observe(&[Config], Instant::now()).is_empty());
        assert_eq!(
            requests.observe(&[Config, Inventory], Instant::now()),
            [Inventory]
        );
        assert!(requests.take(Config).is_some());
        assert!(requests.take(Inventory).is_some());
    }

    #[test]
    fn a_packages_request_is_one_report_per_episode_like_the_others() {
        // P2-AGENT-PACKAGES: `packages` has its own episode, untouched by the other types.
        let requests = ReportRequests::new();
        let t0 = Instant::now();
        assert_eq!(
            requests.observe(&[Config, Inventory, Packages], t0),
            [Config, Inventory, Packages]
        );
        assert_eq!(requests.take(Packages), Some(t0));
        assert!(requests.observe(&[Packages], t0).is_empty());
        assert_eq!(requests.take(Packages), None);
        requests.answered(Packages, t0 + Duration::from_secs(5));
        let next = t0 + Duration::from_secs(600);
        assert_eq!(requests.observe(&[Packages], next), [Packages]);
        assert_eq!(requests.take(Packages), Some(next));
        // Config's request, never taken, is still pending; inventory's episode ended.
        assert_eq!(requests.take(Config), Some(t0));
        assert_eq!(requests.take(Inventory), Some(t0));
    }

    #[test]
    fn names() {
        assert_eq!(ReportType::from_name("config"), Some(Config));
        assert_eq!(ReportType::from_name("inventory"), Some(Inventory));
        assert_eq!(ReportType::from_name("packages"), Some(Packages));
        assert_eq!(ReportType::from_name("vulnerabilities"), None);
        assert_eq!(ReportType::from_name("Config"), None);
    }
}
