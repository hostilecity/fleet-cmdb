//! The heartbeat and inventory intervals in force, shared by both loops (ADR 0019).
//!
//! Each starts at the configured `interval_seconds`. The heartbeat loop applies the server's
//! `directives.intervals` from every heartbeat response, clamped to the configured `min..=max`, so the
//! server can shed load fleet-wide without an agent release but never push an agent outside what its
//! operator allowed. A response without an interval for one of them means the server has no
//! preference, and that interval returns to the configured one. Nothing is persisted: after a restart
//! the configured values apply until the first heartbeat response.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::envelope::ServerIntervals;
use crate::config::Interval;

/// The intervals in force.
#[derive(Debug)]
pub struct Intervals {
    heartbeat: Interval,
    inventory: Interval,
    heartbeat_now: AtomicU64,
    inventory_now: AtomicU64,
}

impl Intervals {
    pub fn new(heartbeat: Interval, inventory: Interval) -> Self {
        Self {
            heartbeat,
            inventory,
            heartbeat_now: AtomicU64::new(heartbeat.start.as_secs()),
            inventory_now: AtomicU64::new(inventory.start.as_secs()),
        }
    }

    pub fn heartbeat(&self) -> Duration {
        Duration::from_secs(self.heartbeat_now.load(Ordering::Relaxed))
    }

    pub fn inventory(&self) -> Duration {
        Duration::from_secs(self.inventory_now.load(Ordering::Relaxed))
    }

    /// Applies what the server asked for in one heartbeat response, logging each change.
    pub fn apply(&self, server: ServerIntervals) {
        apply_one(
            "heartbeat",
            &self.heartbeat,
            &self.heartbeat_now,
            server.heartbeat_seconds,
        );
        apply_one(
            "inventory",
            &self.inventory,
            &self.inventory_now,
            server.inventory_seconds,
        );
    }
}

fn apply_one(name: &'static str, config: &Interval, now: &AtomicU64, requested: Option<u64>) {
    let applied = requested.map_or(config.start, |s| config.clamp_server_value(s));
    let applied_seconds = applied.as_secs();
    let previous = now.swap(applied_seconds, Ordering::Relaxed);
    if previous == applied_seconds {
        return;
    }
    let (min_seconds, max_seconds) = (config.min.as_secs(), config.max.as_secs());
    match requested {
        Some(requested_seconds) if requested_seconds != applied_seconds => tracing::warn!(
            interval = name,
            requested_seconds,
            applied_seconds,
            min_seconds,
            max_seconds,
            "the server asked for an interval outside this agent's configured bounds; using the nearest bound"
        ),
        Some(requested_seconds) => tracing::info!(
            interval = name,
            requested_seconds,
            applied_seconds,
            previous_seconds = previous,
            "interval set by the server"
        ),
        None => tracing::info!(
            interval = name,
            applied_seconds,
            previous_seconds = previous,
            "the server no longer sets this interval; using the configured one"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::capture::logs_of;

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

    fn server(heartbeat: Option<u64>, inventory: Option<u64>) -> ServerIntervals {
        ServerIntervals {
            heartbeat_seconds: heartbeat,
            inventory_seconds: inventory,
        }
    }

    #[test]
    fn starts_at_the_configured_intervals() {
        let i = intervals();
        assert_eq!((i.heartbeat(), i.inventory()), (secs(60), secs(900)));
    }

    #[test]
    fn server_values_within_bounds_are_applied_and_logged_once() {
        let i = intervals();
        let ((), logs) = logs_of(|| i.apply(server(Some(120), Some(1800))));
        assert_eq!((i.heartbeat(), i.inventory()), (secs(120), secs(1800)));
        assert_eq!(
            logs.matches("interval set by the server").count(),
            2,
            "{logs}"
        );
        assert!(logs.contains("interval=\"heartbeat\" requested_seconds=120 applied_seconds=120"));
        // The same values again change nothing and log nothing.
        let ((), logs) = logs_of(|| i.apply(server(Some(120), Some(1800))));
        assert!(logs.is_empty(), "{logs}");
    }

    #[test]
    fn server_values_are_clamped_to_the_configured_bounds() {
        let i = intervals();
        let ((), logs) = logs_of(|| i.apply(server(Some(1), Some(u64::MAX))));
        assert_eq!((i.heartbeat(), i.inventory()), (secs(30), secs(21_600)));
        assert!(
            logs.contains("outside this agent's configured bounds"),
            "{logs}"
        );
        assert!(logs.contains("requested_seconds=1 applied_seconds=30 min_seconds=30"));
        i.apply(server(Some(0), Some(0)));
        assert_eq!((i.heartbeat(), i.inventory()), (secs(30), secs(300)));
    }

    #[test]
    fn an_absent_value_returns_to_the_configured_interval() {
        let i = intervals();
        i.apply(server(Some(300), Some(3600)));
        let ((), logs) = logs_of(|| i.apply(server(None, Some(3600))));
        assert_eq!((i.heartbeat(), i.inventory()), (secs(60), secs(3600)));
        assert!(logs.contains("no longer sets this interval"), "{logs}");
        i.apply(ServerIntervals::default());
        assert_eq!((i.heartbeat(), i.inventory()), (secs(60), secs(900)));
    }
}
