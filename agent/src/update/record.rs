//! The updater's records in the state directory (see [`super::layout`] for the file names). Every write
//! is atomic (`state::write_record`), so a crash leaves the old record or the new one.
//!
//! The update record is the supervisor's memory: it says how far an update got, so a supervisor that
//! was killed, or a VM that rebooted, can be resumed from the same place. Nothing in it comes from the
//! server except the rollout id and the version, and both are validated before they are used.

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::layout::{MARKER_FILE, RECORD_FILE, RESULT_FILE};

const MAX_RECORD_BYTES: u64 = 16 * 1024;

/// How far an update has got. Only the supervisor moves it forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Verified and staged by the agent; the supervisor has not switched yet.
    Staged,
    /// The supervisor is installing the version and is about to swap `current`.
    Switching,
    /// `current` points to the new version; waiting for it to confirm.
    Switched,
    /// Going back to the previous version.
    RollingBack,
    /// The new version confirmed; only clean-up remains.
    Confirmed,
}

/// The update in progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub rollout_id: u64,
    /// The version being installed.
    pub version: String,
    /// The version that was running, and that a rollback returns to.
    pub from_version: String,
    pub phase: Phase,
    /// When the update was staged, as seconds since the Unix epoch.
    pub started_unix: u64,
    /// The `report_id` of the outcome, fixed when the update starts, so an outcome written twice by a
    /// resumed supervisor is one result to the server.
    pub report_id: String,
    /// How long the new version has to confirm, in seconds (from the config when the update started).
    pub confirm_seconds: u64,
    /// When the new version must have confirmed, as seconds since the Unix epoch. Set when the service
    /// is restarted into it.
    #[serde(default)]
    pub deadline_unix: Option<u64>,
    /// The service has been restarted for the current phase.
    #[serde(default)]
    pub restarted: bool,
    #[serde(default)]
    pub rollback_reason: Option<String>,
    /// The kernel's boot id when the update was staged. A different one later means the VM restarted
    /// during the update, and an update the VM restarted under is never confirmed (ADR 0018).
    #[serde(default)]
    pub boot_id: Option<String>,
}

impl Record {
    /// Whether the VM has restarted since the update was staged. Unknown (either boot id unreadable)
    /// counts as not restarted; the deadline still applies.
    pub fn rebooted(&self, boot_id: Option<&str>) -> bool {
        matches!((self.boot_id.as_deref(), boot_id), (Some(then), Some(now)) if then != now)
    }

    /// `current` has been (or may have been) swapped to the new version.
    pub fn past_switch(&self) -> bool {
        matches!(
            self.phase,
            Phase::Switched | Phase::RollingBack | Phase::Confirmed
        )
    }
}

/// `Ok(None)` from [`StateFile::read`] when no update is in progress.
impl StateFile for Record {
    const NAME: &str = RECORD_FILE;
}

/// Written by the new version after its first heartbeat the server acknowledged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marker {
    pub rollout_id: u64,
    pub version: String,
    pub pid: u32,
    pub confirmed_at: String,
    /// When the server's acknowledgement arrived, as seconds since the Unix epoch.
    #[serde(default)]
    pub confirmed_unix: u64,
    /// The boot it was written in.
    #[serde(default)]
    pub boot_id: Option<String>,
}

impl StateFile for Marker {
    const NAME: &str = MARKER_FILE;
}

impl Marker {
    /// Whether this marker confirms `record`'s update: the same rollout and version, written in the
    /// boot the update started in, and no later than the deadline. A confirmation that came too late,
    /// or after the VM restarted, is not one (ADR 0018), whoever reads it and whenever.
    pub fn confirms(&self, record: &Record) -> bool {
        self.rollout_id == record.rollout_id
            && self.version == record.version
            && !record.rebooted(self.boot_id.as_deref())
            && record
                .deadline_unix
                .is_none_or(|deadline| self.confirmed_unix <= deadline)
    }
}

/// How an update ended, as `update-result.request` calls it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Succeeded,
    Failed,
    RolledBack,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::RolledBack => "rolled_back",
        }
    }
}

/// An outcome waiting to be accepted by the server (`POST /api/v1/update-results`). It stays on disk,
/// with the same `report_id`, until the server accepts it, whatever restarts happen meanwhile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingResult {
    pub report_id: String,
    pub rollout_id: u64,
    pub version: String,
    pub outcome: Outcome,
    pub reason: Option<String>,
    pub occurred_at: String,
}

/// Longest reason the API accepts.
pub const MAX_REASON_CHARS: usize = 500;

impl StateFile for PendingResult {
    const NAME: &str = RESULT_FILE;
}

/// A reason as the API wants it: plain text on one line, at most [`MAX_REASON_CHARS`] characters,
/// never empty.
pub fn reason(text: &str) -> String {
    let one_line = crate::logging::sanitize(text, MAX_REASON_CHARS);
    let trimmed = one_line.trim();
    if trimmed.is_empty() {
        "no reason was recorded".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// A JSON record in the state directory, read, written atomically, and removed by name.
pub trait StateFile: Serialize + for<'de> Deserialize<'de> {
    const NAME: &str;

    /// `Ok(None)` when there is none. A record that cannot be read is an error.
    fn read(state_dir: &Path) -> io::Result<Option<Self>> {
        match crate::state::read_record(state_dir, Self::NAME, MAX_RECORD_BYTES)? {
            None => Ok(None),
            Some(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| io::Error::other(format!("{} is not valid: {e}", Self::NAME))),
        }
    }

    fn write(&self, state_dir: &Path) -> io::Result<()> {
        let bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        crate::state::write_record(state_dir, Self::NAME, &bytes)
    }

    /// Removing a record that is not there is not an error.
    fn remove(state_dir: &Path) -> io::Result<()> {
        match std::fs::remove_file(state_dir.join(Self::NAME)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_support::TempDir;

    pub fn record() -> Record {
        Record {
            rollout_id: 7,
            version: "0.2.0".into(),
            from_version: "0.1.0".into(),
            phase: Phase::Staged,
            started_unix: 1_767_268_800,
            report_id: "00000000-0000-4000-8000-000000000001".into(),
            confirm_seconds: 300,
            deadline_unix: None,
            restarted: false,
            rollback_reason: None,
            boot_id: Some("boot-1".into()),
        }
    }

    #[test]
    fn records_round_trip_and_a_missing_one_is_none() {
        let dir = TempDir::new();
        assert_eq!(Record::read(dir.root()).unwrap(), None);
        let mut r = record();
        r.write(dir.root()).unwrap();
        assert_eq!(Record::read(dir.root()).unwrap(), Some(r.clone()));
        r.phase = Phase::Switched;
        r.deadline_unix = Some(1_767_268_800);
        r.write(dir.root()).unwrap();
        assert_eq!(Record::read(dir.root()).unwrap(), Some(r));
        Record::remove(dir.root()).unwrap();
        Record::remove(dir.root()).unwrap();
        assert_eq!(Record::read(dir.root()).unwrap(), None);
    }

    #[test]
    fn a_damaged_record_is_an_error_not_an_update() {
        let dir = TempDir::new();
        std::fs::write(dir.path(RECORD_FILE), "{not json").unwrap();
        assert!(Record::read(dir.root()).is_err());
    }

    #[test]
    fn a_marker_confirms_only_its_own_rollout_and_version() {
        let marker = Marker {
            rollout_id: 7,
            version: "0.2.0".into(),
            pid: 1,
            confirmed_at: "2026-01-01T12:00:00Z".into(),
            confirmed_unix: 1_767_268_900,
            boot_id: Some("boot-1".into()),
        };
        assert!(marker.confirms(&record()));
        assert!(
            !Marker {
                rollout_id: 8,
                ..marker.clone()
            }
            .confirms(&record())
        );
        assert!(
            !Marker {
                version: "0.2.1".into(),
                ..marker
            }
            .confirms(&record())
        );
    }

    #[test]
    fn a_marker_after_the_deadline_or_from_another_boot_confirms_nothing() {
        let mut rec = record();
        rec.deadline_unix = Some(1_767_269_100);
        let marker = Marker {
            rollout_id: 7,
            version: "0.2.0".into(),
            pid: 1,
            confirmed_at: "2026-01-01T12:05:00Z".into(),
            confirmed_unix: 1_767_269_100,
            boot_id: Some("boot-1".into()),
        };
        assert!(marker.confirms(&rec), "on the deadline is in time");
        let late = Marker {
            confirmed_unix: 1_767_269_101,
            ..marker.clone()
        };
        assert!(!late.confirms(&rec));
        let other_boot = Marker {
            boot_id: Some("boot-2".into()),
            ..marker
        };
        assert!(!other_boot.confirms(&rec));
        assert!(rec.rebooted(Some("boot-2")));
        assert!(!rec.rebooted(Some("boot-1")));
        assert!(!rec.rebooted(None));
    }

    #[test]
    fn reasons_are_one_line_bounded_and_never_empty() {
        assert_eq!(reason("a\nb\tc"), "a b c");
        assert_eq!(reason("   "), "no reason was recorded");
        assert_eq!(reason(&"x".repeat(900)).chars().count(), MAX_REASON_CHARS);
    }
}
