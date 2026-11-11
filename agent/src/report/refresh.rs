//! Report refreshes for the `refresh_reports` task (P3-A04, #36): how a task asks the report loops for
//! one fresh report of each type, and learns what became of it.
//!
//! The task never collects or sends anything itself. It asks ([`Refresh::ask`]); each report loop takes
//! the ask on its next poll ([`Refresh::take`], within [`super::REQUEST_POLL`]) and hands it to its
//! reporter as a request, exactly as it does the heartbeat's `report_request` directive (DEC-13). The
//! report is then collected, sent, retried, and deduplicated by the one reporter of its type, so a
//! scheduled report, a directive, and a task due at the same moment give one report, not two (P3-A04
//! AC: no duplicate snapshots). When the reporter has finished with a requested report (accepted, or
//! rejected for its content), the loop settles it here ([`Refresh::settle`]) with the time it was
//! built, and the task counts it only if it was built after the task asked: a report collected
//! earlier, still waiting for its retry, is not a fresh one.

use std::sync::{Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::requests::ReportType;

/// How a requested report ended, as a reporter tells its loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Done {
    /// When the report was built (its facts collected).
    pub built_at: Instant,
    /// `true` if the server accepted it, `false` if it rejected it for its content.
    pub accepted: bool,
}

#[derive(Debug, Default, Clone, Copy)]
struct Slot {
    /// A task asked for a report of this type at this time, and no loop has taken the ask yet.
    asked: Option<Instant>,
    /// The latest requested report of this type to end.
    done: Option<Done>,
}

/// Shared between the report loops and the `refresh_reports` task.
#[derive(Default)]
pub struct Refresh {
    slots: Mutex<[Slot; 3]>,
    changed: Condvar,
}

fn index(ty: ReportType) -> usize {
    ReportType::ALL
        .iter()
        .position(|t| *t == ty)
        .unwrap_or_default()
}

impl Refresh {
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks for one fresh report of each of `types`. Returns the time of the ask: a report counts
    /// for it only if it was built at that time or later ([`Refresh::outcome`]).
    pub fn ask(&self, types: &[ReportType]) -> Instant {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        for ty in types {
            let slot = &mut slots[index(*ty)];
            // An earlier ask not yet taken is served by the same report, built after both.
            slot.asked.get_or_insert(now);
        }
        now
    }

    /// Withdraws the asks for `types` that no loop has taken yet (the task was stopped).
    pub fn withdraw(&self, types: &[ReportType]) {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        for ty in types {
            slots[index(*ty)].asked = None;
        }
    }

    /// For the report loop of `ty`: whether a task asked for a report, taking the ask.
    pub fn take(&self, ty: ReportType) -> bool {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)[index(ty)]
            .asked
            .take()
            .is_some()
    }

    /// For the report loop of `ty`: a requested report ended.
    pub fn settle(&self, ty: ReportType, done: Done) {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)[index(ty)].done = Some(done);
        self.changed.notify_all();
    }

    /// What became of the report of `ty` asked for at `since`: `Some(true)` accepted, `Some(false)`
    /// rejected, `None` not yet ended (or only a report built before `since` did).
    pub fn outcome(&self, ty: ReportType, since: Instant) -> Option<bool> {
        let slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        slots[index(ty)]
            .done
            .filter(|done| done.built_at >= since)
            .map(|done| done.accepted)
    }

    /// Waits up to `timeout` for a report to be settled.
    pub fn wait(&self, timeout: Duration) {
        let slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = self
            .changed
            .wait_timeout(slots, timeout)
            .unwrap_or_else(PoisonError::into_inner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ReportType::{Config, Inventory, Packages};

    #[test]
    fn an_ask_is_taken_once_per_type() {
        let refresh = Refresh::new();
        assert!(!refresh.take(Config));
        refresh.ask(&[Config, Packages]);
        assert!(refresh.take(Config));
        assert!(!refresh.take(Config));
        assert!(!refresh.take(Inventory));
        assert!(refresh.take(Packages));
    }

    #[test]
    fn only_a_report_built_after_the_ask_counts() {
        let refresh = Refresh::new();
        let before = Instant::now();
        let since = refresh.ask(&ReportType::ALL);
        assert_eq!(refresh.outcome(Config, since), None);
        // A report collected before the task asked, accepted now: not fresh.
        refresh.settle(
            Config,
            Done {
                built_at: before,
                accepted: true,
            },
        );
        assert_eq!(refresh.outcome(Config, since), None);
        refresh.settle(
            Config,
            Done {
                built_at: Instant::now(),
                accepted: true,
            },
        );
        assert_eq!(refresh.outcome(Config, since), Some(true));
        refresh.settle(
            Inventory,
            Done {
                built_at: Instant::now(),
                accepted: false,
            },
        );
        assert_eq!(refresh.outcome(Inventory, since), Some(false));
        assert_eq!(refresh.outcome(Packages, since), None);
    }

    #[test]
    fn a_withdrawn_ask_is_not_taken() {
        let refresh = Refresh::new();
        refresh.ask(&ReportType::ALL);
        assert!(refresh.take(Inventory));
        refresh.withdraw(&ReportType::ALL);
        assert!(!refresh.take(Config));
        assert!(!refresh.take(Packages));
    }

    #[test]
    fn wait_returns_when_a_report_is_settled() {
        let refresh = Refresh::new();
        let since = refresh.ask(&[Config]);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(50));
                refresh.settle(
                    Config,
                    Done {
                        built_at: Instant::now(),
                        accepted: true,
                    },
                );
            });
            let started = Instant::now();
            while refresh.outcome(Config, since).is_none() {
                refresh.wait(Duration::from_secs(10));
            }
            assert!(started.elapsed() < Duration::from_secs(5));
        });
    }
}
