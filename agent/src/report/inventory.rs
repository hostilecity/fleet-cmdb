//! The inventory reporter (FR-1.3, P1-A07, DEC-07).
//!
//! A report is sent:
//!
//! - **on startup**, always (FR-1.3);
//! - **on schedule**, one inventory interval (minus up to 10% jitter) after the previous report was
//!   accepted or rejected;
//! - **on change**: every [`CHANGE_CHECK_INTERVAL`] the facts are collected and the hash of their stable
//!   part ([`StableHash`]) is compared with that of the last report. A difference sends a report at
//!   once; a volatile-only difference (free memory, free disk space, uptime) does not.
//!
//! Each report gets a new `report_id` (UUIDv4). A failed send is retried by the retry policy
//! ([`crate::retry`]) with the **same** report id and body, so the server can discard a duplicate. No
//! report is queued or replayed: while a report waits for its retry, a newer report replaces it when the
//! stable facts change or when it is older than one inventory interval, so the server receives current
//! state when it returns. A report the server rejects for its content (`400`, `413`, `422`) is not
//! retried, since the same body would be rejected again; the next report follows the normal schedule.
//!
//! After every accepted report, its stable hash, boot identifier, and agent version are saved in the
//! state directory ([`RECORD_NAME`]). A restart sends the startup report and logs whether the stable
//! facts changed and whether the host rebooted since the last accepted report; a missing or corrupt
//! record is treated as none.

use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use super::intervals::Intervals;
use super::time::rfc3339;
use super::{Transport, new_report_id};
use crate::client::ApiError;
use crate::collect::Inventory;
use crate::retry::{Backoff, Rng};
use crate::{AGENT_SCHEMA_VERSION, AGENT_VERSION};

pub const INVENTORY_PATH: &str = "/api/v1/reports/inventory";

/// How often the stable facts are checked for a change.
pub const CHANGE_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// The state record of the last accepted report, in the state directory.
pub const RECORD_NAME: &str = "inventory.json";
const MAX_RECORD_BYTES: u64 = 4096;

/// `inventory.request` (docs/api/schemas/v1): the envelope plus the collected facts.
#[derive(Debug, Serialize)]
pub struct InventoryReport<'a> {
    pub schema_version: u32,
    pub agent_version: &'static str,
    pub report_id: &'a str,
    pub collected_at: String,
    #[serde(flatten)]
    pub facts: &'a Inventory,
}

/// A hash of the stable facts and the agent version (DEC-07): 128-bit FNV-1a over their JSON. It
/// detects change; it is not a security boundary (a collision would delay a report by at most one
/// inventory interval).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StableHash(u128);

impl StableHash {
    pub fn of(inventory: &Inventory) -> Self {
        const OFFSET: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
        const PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;
        // Serialising plain data cannot fail; an empty input would still give a fixed hash.
        let bytes = serde_json::to_vec(&(AGENT_VERSION, inventory.stable())).unwrap_or_default();
        let mut hash = OFFSET;
        for byte in bytes {
            hash ^= u128::from(byte);
            hash = hash.wrapping_mul(PRIME);
        }
        Self(hash)
    }

    fn parse(text: &str) -> Option<Self> {
        let hex = text.strip_prefix("fnv1a128:")?;
        if hex.len() != 32 {
            return None;
        }
        u128::from_str_radix(hex, 16).ok().map(Self)
    }
}

impl fmt::Display for StableHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fnv1a128:{:032x}", self.0)
    }
}

/// What the state directory remembers about the last accepted report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub stable_hash: String,
    pub boot_id: Option<String>,
    pub agent_version: String,
    pub report_id: String,
    pub reported_at: String,
}

/// Why a report was built; logged with its outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Startup,
    Scheduled,
    Changed,
}

impl Reason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Scheduled => "scheduled",
            Self::Changed => "stable_change",
        }
    }
}

/// A built report waiting to be sent, or to be sent again.
#[derive(Debug, Clone)]
struct Pending {
    report_id: String,
    body: serde_json::Value,
    hash: StableHash,
    boot_id: Option<String>,
    reason: Reason,
    built_at: Instant,
}

/// Inventory reporting state across iterations of the loop.
pub struct Reporter<'a, R: Rng> {
    intervals: &'a Intervals,
    state_dir: PathBuf,
    backoff: Backoff<R>,
    rng: R,
    /// The report being sent or waiting for its retry.
    pending: Option<Pending>,
    /// No send before this, after a failure.
    retry_at: Option<Instant>,
    /// The stable hash of the last report that was accepted or rejected (or, before any, the record's).
    baseline: Option<StableHash>,
    /// The last accepted report, from the state directory at start and then kept up to date.
    record: Option<Record>,
    /// When the previous report was accepted or rejected, and this cycle's jitter in per mille.
    last_done: Option<Instant>,
    jitter_permille: u64,
    next_check: Instant,
    /// No report is built before this, after one could not be built.
    hold_until: Option<Instant>,
    /// Generates report ids; replaceable in tests.
    new_id: fn() -> std::io::Result<String>,
}

impl<'a, R: Rng> Reporter<'a, R> {
    /// Loads the state record from `state_dir`. The first [`Reporter::tick`] sends the startup report.
    pub fn new(intervals: &'a Intervals, state_dir: PathBuf, backoff: Backoff<R>, rng: R) -> Self {
        let record = load_record(&state_dir);
        Self {
            intervals,
            baseline: record
                .as_ref()
                .and_then(|r| StableHash::parse(&r.stable_hash)),
            record,
            state_dir,
            backoff,
            rng,
            pending: None,
            retry_at: None,
            last_done: None,
            jitter_permille: 0,
            next_check: Instant::now(),
            hold_until: None,
            new_id: new_report_id,
        }
    }

    /// The report id waiting to be sent, if any.
    #[cfg(test)]
    pub fn pending_report_id(&self) -> Option<&str> {
        self.pending.as_ref().map(|p| p.report_id.as_str())
    }

    /// Does whatever is due at `now` and returns when to call again. `collect` gathers the facts; the
    /// caller keeps one [`crate::collect::Collector`] for the agent's lifetime.
    pub fn tick(
        &mut self,
        now: Instant,
        collect: &mut dyn FnMut() -> Inventory,
        transport: &dyn Transport,
    ) -> Instant {
        let interval = self.intervals.inventory();
        if now >= self.build_due_at(now, interval) {
            let reason = match &self.pending {
                // A report still waiting for its retry is too old to send: replace it with current
                // state, keeping its reason.
                Some(pending) => pending.reason,
                None if self.last_done.is_none() => Reason::Startup,
                None => Reason::Scheduled,
            };
            let inventory = collect();
            self.build(reason, inventory, now);
            self.next_check = now + CHANGE_CHECK_INTERVAL;
        } else if now >= self.next_check {
            self.next_check = now + CHANGE_CHECK_INTERVAL;
            let inventory = collect();
            let hash = StableHash::of(&inventory);
            let reference = self.pending.as_ref().map(|p| p.hash).or(self.baseline);
            if reference != Some(hash) {
                self.build(Reason::Changed, inventory, now);
            } else {
                tracing::trace!("stable facts unchanged");
            }
        }

        if self.pending.is_some() && self.retry_at.is_none_or(|at| now >= at) {
            self.send(transport, now);
        }

        let mut wake = self.next_check.min(self.build_due_at(now, interval));
        if self.pending.is_some()
            && let Some(at) = self.retry_at
        {
            wake = wake.min(at);
        }
        wake
    }

    /// When the next report is due to be built: at once at startup, one interval (less this cycle's
    /// jitter) after the previous report was done with, or when a report still waiting for its retry
    /// becomes one interval old. Never before `hold_until`, after a report could not be built.
    fn build_due_at(&self, now: Instant, interval: Duration) -> Instant {
        let due = match (&self.pending, self.last_done) {
            (Some(pending), _) => pending.built_at + interval,
            (None, Some(done)) => done + interval - interval * self.jitter_permille as u32 / 1000,
            (None, None) => now,
        };
        self.hold_until.map_or(due, |hold| due.max(hold))
    }

    /// Builds a new report with a new id, replacing any report still waiting.
    fn build(&mut self, reason: Reason, inventory: Inventory, now: Instant) {
        let report_id = match (self.new_id)() {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(
                    reason = reason.as_str(),
                    retry_in_seconds = CHANGE_CHECK_INTERVAL.as_secs(),
                    "cannot generate a report id ({e}); the inventory report is postponed"
                );
                self.hold_until = Some(now + CHANGE_CHECK_INTERVAL);
                return;
            }
        };
        let hash = StableHash::of(&inventory);
        let report = InventoryReport {
            schema_version: AGENT_SCHEMA_VERSION,
            agent_version: AGENT_VERSION,
            report_id: &report_id,
            collected_at: rfc3339(SystemTime::now()),
            facts: &inventory,
        };
        let body = match serde_json::to_value(&report) {
            Ok(body) => body,
            Err(e) => {
                tracing::error!(
                    reason = reason.as_str(),
                    retry_in_seconds = CHANGE_CHECK_INTERVAL.as_secs(),
                    "cannot encode the inventory report ({e}); the inventory report is postponed"
                );
                self.hold_until = Some(now + CHANGE_CHECK_INTERVAL);
                return;
            }
        };
        self.hold_until = None;
        let span = tracing::info_span!("inventory", report_id = report_id.as_str());
        let _entered = span.enter();
        if let Some(old) = &self.pending {
            tracing::info!(
                replaced_report_id = old.report_id.as_str(),
                reason = reason.as_str(),
                "replacing an unsent inventory report with current state"
            );
        } else if reason == Reason::Startup {
            // The baseline is still the record's here: no report has been done with since start.
            let previous = self.record.as_ref();
            tracing::info!(
                stable_changed = self.baseline != Some(hash),
                rebooted = previous.is_none_or(|r| r.boot_id != inventory.boot_id),
                last_report_id = previous.map_or("", |r| r.report_id.as_str()),
                warnings = inventory.warnings.len(),
                "sending the startup inventory report"
            );
        } else if reason == Reason::Changed {
            tracing::info!(
                warnings = inventory.warnings.len(),
                "stable facts changed; sending an inventory report"
            );
        }
        self.pending = Some(Pending {
            report_id,
            body,
            hash,
            boot_id: inventory.boot_id.clone(),
            reason,
            built_at: now,
        });
    }

    fn send(&mut self, transport: &dyn Transport, now: Instant) {
        let Some(pending) = self.pending.as_ref() else {
            return;
        };
        let span = tracing::info_span!("inventory", report_id = pending.report_id.as_str());
        let _entered = span.enter();
        let reason = pending.reason.as_str();
        let attempt = self.backoff.failures() + 1;
        match transport.post(INVENTORY_PATH, &pending.body) {
            Ok(response) => {
                let request_id = response.request_id.as_deref().unwrap_or("");
                let duplicate = response
                    .body
                    .get("duplicate")
                    .and_then(serde_json::Value::as_bool);
                let echoed = response
                    .body
                    .get("report_id")
                    .and_then(serde_json::Value::as_str);
                if echoed != Some(pending.report_id.as_str()) {
                    tracing::warn!(
                        request_id,
                        "the server's reply does not name this report; treating it as accepted"
                    );
                }
                if duplicate == Some(true) {
                    tracing::info!(
                        reason,
                        attempt,
                        request_id,
                        "inventory report was a duplicate: the server already had it"
                    );
                } else {
                    tracing::info!(reason, attempt, request_id, "inventory report sent");
                }
                self.accepted(now);
            }
            Err(error) if rejected_for_content(&error) => {
                let (code, message) = match &error {
                    ApiError::Rejected { code, message, .. } => (code.as_str(), message.as_str()),
                    _ => ("payload_too_large", ""),
                };
                tracing::error!(
                    reason,
                    status = error.status(),
                    code,
                    server_message = message,
                    request_id = error.request_id().unwrap_or(""),
                    "the server rejected the inventory report; it will not be retried, and the next report follows the normal schedule"
                );
                self.finished(now);
            }
            Err(error) => {
                self.retry_at = Some(now + self.backoff.on_failure(&error));
            }
        }
    }

    /// The pending report was accepted: remember it, here and in the state directory.
    fn accepted(&mut self, now: Instant) {
        let Some(pending) = self.pending.as_ref() else {
            return;
        };
        let record = Record {
            stable_hash: pending.hash.to_string(),
            boot_id: pending.boot_id.clone(),
            agent_version: AGENT_VERSION.to_owned(),
            report_id: pending.report_id.clone(),
            reported_at: rfc3339(SystemTime::now()),
        };
        let saved = serde_json::to_vec(&record)
            .map_err(std::io::Error::other)
            .and_then(|bytes| crate::state::write_record(&self.state_dir, RECORD_NAME, &bytes));
        if let Err(e) = saved {
            tracing::warn!(
                state_dir = %self.state_dir.display(),
                "cannot save the inventory state ({e}); after a restart the agent cannot tell whether the stable facts changed meanwhile"
            );
        }
        self.record = Some(record);
        self.finished(now);
    }

    /// The pending report is done with (accepted or rejected): schedule the next one.
    fn finished(&mut self, now: Instant) {
        if let Some(pending) = self.pending.take() {
            self.baseline = Some(pending.hash);
        }
        self.retry_at = None;
        self.backoff.on_success();
        self.last_done = Some(now);
        self.jitter_permille = self.rng.next_u64() % 101;
    }
}

/// `400`, `413`, and `422` say the body itself is unacceptable; sending it again cannot help.
fn rejected_for_content(error: &ApiError) -> bool {
    matches!(
        error,
        ApiError::PayloadTooLarge { .. }
            | ApiError::Rejected {
                status: 400 | 422,
                ..
            }
    )
}

fn load_record(state_dir: &std::path::Path) -> Option<Record> {
    let bytes = match crate::state::read_record(state_dir, RECORD_NAME, MAX_RECORD_BYTES) {
        Ok(bytes) => bytes?,
        Err(e) => {
            tracing::warn!(
                record = RECORD_NAME,
                "cannot read the inventory state ({e}); starting without it"
            );
            return None;
        }
    };
    match serde_json::from_slice::<Record>(&bytes) {
        Ok(record) if StableHash::parse(&record.stable_hash).is_some() => Some(record),
        _ => {
            tracing::warn!(
                record = RECORD_NAME,
                "the inventory state is corrupt; starting without it"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests;
