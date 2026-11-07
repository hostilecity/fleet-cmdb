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
//! that fails says nothing and changes nothing.
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
}

impl ReportType {
    pub const ALL: [ReportType; 2] = [ReportType::Config, ReportType::Inventory];

    /// The type's name in `directives.report_request.types`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Inventory => "inventory",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.name() == name)
    }

    fn index(self) -> usize {
        match self {
            Self::Config => 0,
            Self::Inventory => 1,
        }
    }
}

#[derive(Default)]
struct Inner {
    /// The type is in the heartbeat responses of the current episode.
    present: [bool; 2],
    /// When the episode's request was raised, until a report loop takes it.
    pending: [Option<Instant>; 2],
}

/// Shared between the heartbeat loop, which observes, and the report loops, which take.
#[derive(Default)]
pub struct ReportRequests(Mutex<Inner>);

impl ReportRequests {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records what one accepted heartbeat response asked for (`wanted` empty when it had no
    /// `report_request`). Returns the types whose episode just began.
    pub fn observe(&self, wanted: &[ReportType], now: Instant) -> Vec<ReportType> {
        let mut inner = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let mut began = Vec::new();
        for ty in ReportType::ALL {
            let i = ty.index();
            if wanted.contains(&ty) {
                if !inner.present[i] {
                    inner.present[i] = true;
                    inner.pending[i] = Some(now);
                    began.push(ty);
                }
            } else {
                inner.present[i] = false;
            }
        }
        began
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
    use ReportType::{Config, Inventory};

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
    fn names() {
        assert_eq!(ReportType::from_name("config"), Some(Config));
        assert_eq!(ReportType::from_name("inventory"), Some(Inventory));
        assert_eq!(ReportType::from_name("packages"), None);
        assert_eq!(ReportType::from_name("Config"), None);
    }
}
