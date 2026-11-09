//! The durable local task ledger (FR-3.2, FR-3.3, AC-3.3, P3-A02).
//!
//! One append-only file in the state directory, [`LEDGER_FILE`], records what happened to every task
//! this agent was given, one line per step:
//!
//! - `received`: the poll delivered the task (id, type, catalog version, timeout, parameters);
//! - `started`: the agent is about to run it. **Written and flushed before the server is told and
//!   before anything runs**, so after a crash the agent knows the task may have run;
//! - `finished`: the outcome (and reason) the agent decided or observed. The full result body, with
//!   any output, is in [`RESULT_FILE`] first, so the ledger lines stay small;
//! - `reported`: the server accepted the result (or refused it for good, `rejected`);
//! - `done`: what compaction keeps of a reported task, enough to know its id was seen;
//! - `hold`: the ledger was found damaged; run nothing until `until_unix` (below).
//!
//! **The rules this module enforces.** A task id is received once: a second delivery of an id already
//! in the ledger, in any state, is never received again ([`Receipt::Known`]), so it can never be run
//! twice (duplicate delivery, C7, R2). `started` is only possible straight after `received`, once.
//! Every append is `write` then `fsync` of the file, and the directory is flushed when the file is
//! created or replaced, so a record the caller saw succeed survives a crash or a power loss. An append
//! that fails leaves the ledger unusable ([`LedgerError::Poisoned`]) until it is opened again, because
//! only the file says what is durable.
//!
//! **Lines.** `<16 hex digits of SHA-256 of the JSON> <JSON>\n`. A line whose sum or JSON is wrong is
//! damage. A line with the right sum that this version cannot read (a newer version's step) is an
//! *unknown state* for its task: that task is reported, never run.
//!
//! **Opening ([`Ledger::open`]).**
//!
//! - A bad or unterminated **last** line is a torn tail: the write that made it never returned, so
//!   nothing acted on it. It is dropped (the file is rewritten atomically without it). A complete,
//!   valid last line that only lacks its newline is kept, which is the safe reading: a `started` kept
//!   this way is reported `interrupted`, never run.
//! - A bad line **before** the last one, or a file that cannot be read (too large, not a regular file),
//!   means a record that was flushed, and maybe acted on, is lost: it could have been the `started` of
//!   a task the server sends again. The damaged file is kept beside the ledger as [`DAMAGED_FILE`] for
//!   inspection, the readable records are kept, and a `hold` record is added: until it ends the agent
//!   runs nothing (callers ask [`Ledger::held`]), and tasks it receives are reported, not run. The hold
//!   lasts [`hold_seconds`], the longest a task may wait to start (the catalog's `expiry_seconds`)
//!   plus the longest it may run: by then every task that existed before the damage was found has
//!   expired or ended on the server, which never redelivers a started task as runnable (P3-S03).
//!
//! **Size.** A record is at most [`MAX_RECORD_BYTES`] (parameters at most [`MAX_PARAMETERS_BYTES`] as
//! JSON) and the file at most [`MAX_LEDGER_BYTES`]. Once the file passes [`COMPACT_AT_BYTES`] and
//! every task in it is reported, it is rewritten atomically with one `done` line for each of the last
//! [`KEEP_DONE`] tasks, and an active hold. A ledger that is full and cannot be compacted (a task is
//! still unreported) receives nothing more ([`LedgerError::Full`]): the agent stops taking tasks rather
//! than forget one.
//!
//! **One writer.** The ledger holds an exclusive lock ([`LOCK_FILE`]) while open, so a second agent
//! process on the same state directory cannot interleave lines.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fsx::{self, Lock};
use crate::report::rfc3339;

use super::catalog::Catalog;

/// The ledger, in the state directory.
pub const LEDGER_FILE: &str = "task-ledger.jsonl";
/// A damaged ledger, kept for inspection when one is found (the latest only).
pub const DAMAGED_FILE: &str = "task-ledger.damaged";
/// Held while the ledger is open, so only one process writes it.
pub const LOCK_FILE: &str = "task-ledger.lock";
/// The result of the task that finished last, until the server accepts it (one task at a time).
pub const RESULT_FILE: &str = "task-result.json";

/// Largest ledger file read. Compaction keeps a healthy ledger far below it.
pub const MAX_LEDGER_BYTES: u64 = 1024 * 1024;
/// Compaction runs once the file is larger than this and every task in it is reported.
pub const COMPACT_AT_BYTES: u64 = 256 * 1024;
/// How many reported task ids compaction keeps.
pub const KEEP_DONE: usize = 1000;
/// Largest line, newline included.
pub const MAX_RECORD_BYTES: usize = 16 * 1024;
/// Largest parameters object, as JSON (the server's own limit, P3-S01).
pub const MAX_PARAMETERS_BYTES: usize = 4096;
/// Largest result file ([`RESULT_FILE`]): output is bounded well below this (P3-A03, P3-S04).
pub const MAX_RESULT_BYTES: u64 = 2 * 1024 * 1024;

/// Room [`Ledger::receive`] leaves for the steps after `received` (each well under 1 KiB).
const RESERVE_BYTES: u64 = 4 * 1024;
/// Mode of the ledger and the result file.
const FILE_MODE: u32 = 0o600;
/// Hex digits of the line checksum.
const SUM_DIGITS: usize = 16;
/// Used when the catalog cannot be read: the 24-hour default expiry plus the longest timeout.
const FALLBACK_HOLD_SECONDS: u64 = 24 * 60 * 60 + 60 * 60;

/// How a task ended, as the result API names it (P3-S04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
    Refused,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
            Self::Refused => "refused",
        }
    }
}

/// One ledger line's record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
enum Entry {
    Received {
        task_id: String,
        task_type: String,
        catalog_version: u32,
        timeout_seconds: u64,
        parameters: Value,
        at: String,
    },
    Started {
        task_id: String,
        at: String,
    },
    Finished {
        task_id: String,
        outcome: Outcome,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        at: String,
    },
    Reported {
        task_id: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        rejected: bool,
        at: String,
    },
    Done {
        task_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        outcome: Option<Outcome>,
        at: String,
    },
    Hold {
        until_unix: u64,
        why: String,
        at: String,
    },
}

/// Where a task is, as the ledger records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Delivered and recorded; never started, so nothing of it ran.
    Received,
    /// `started` is recorded and nothing after it: the task may have run.
    Started,
    /// The outcome is decided; the server has not accepted the result yet.
    Finished {
        outcome: Outcome,
        reason: Option<String>,
    },
    /// The server accepted the result, or refused it for good. Nothing is left to do.
    Reported,
    /// A record this agent version cannot read names the task. It is reported, never run.
    Unknown,
}

impl State {
    /// Order of progress; a record never moves a task back.
    fn rank(&self) -> u8 {
        match self {
            Self::Received => 0,
            Self::Started => 1,
            Self::Unknown => 2,
            Self::Finished { .. } => 3,
            Self::Reported => 4,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Started => "started",
            Self::Finished { .. } => "finished",
            Self::Reported => "reported",
            Self::Unknown => "unknown",
        }
    }
}

/// A task in the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub id: String,
    /// From the `received` record, when there is one.
    pub task_type: Option<String>,
    pub state: State,
    /// Whether a `started` record exists: the task may have run.
    pub started: bool,
    /// When the `started` record was written (agent clock, RFC 3339).
    pub started_at: Option<String>,
}

/// What [`Ledger::receive`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Receipt {
    /// A new task, now recorded as `received`.
    New,
    /// The id is already in the ledger, in this state: it is never received or run again.
    Known(State),
}

/// What opening found and repaired.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Recovery {
    /// A torn last line was dropped.
    pub torn_tail: bool,
    /// The ledger was damaged; why. A hold was recorded and the file kept as [`DAMAGED_FILE`].
    pub damaged: Option<String>,
    /// Lines with a valid checksum this version cannot read.
    pub unknown_records: usize,
    /// The file was compacted.
    pub compacted: bool,
}

#[derive(Debug)]
pub enum LedgerError {
    /// Another process holds the ledger.
    Locked,
    /// The ledger is full and cannot be compacted yet.
    Full,
    /// An append failed earlier; open the ledger again.
    Poisoned,
    /// The caller asked for a step the task's state does not allow (a defect, never a server's doing).
    Step(String),
    /// A value is not one the ledger records (a malformed task id, oversize parameters).
    Invalid(String),
    Io(io::Error),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked => write!(f, "another fleet-agent process holds the task ledger"),
            Self::Full => write!(
                f,
                "the task ledger is full and cannot be compacted until the task in it is reported"
            ),
            Self::Poisoned => write!(f, "a task ledger write failed earlier; it must be reopened"),
            Self::Step(why) | Self::Invalid(why) => write!(f, "{why}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<io::Error> for LedgerError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Whether `id` is a task id the ledger records: a lower-case UUID (P3-S02 gives each task one).
pub fn is_task_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(b),
        })
}

/// How long a hold lasts: the longest a task may wait to start plus the longest it may run.
pub fn hold_seconds() -> u64 {
    Catalog::embedded().map_or(FALLBACK_HOLD_SECONDS, |catalog| {
        let expiry = catalog.tasks.iter().map(|t| t.expiry_seconds).max();
        let timeout = catalog.tasks.iter().map(|t| t.timeout_seconds).max();
        expiry.unwrap_or(0) + timeout.unwrap_or(0)
    })
}

fn unix(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn sum(json: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, json);
    crate::release::hex(&digest.as_ref()[..SUM_DIGITS / 2])
}

/// The line for `entry`, newline included.
fn line(entry: &Entry) -> Result<Vec<u8>, LedgerError> {
    let json = serde_json::to_vec(entry).map_err(io::Error::other)?;
    let mut out = Vec::with_capacity(json.len() + SUM_DIGITS + 2);
    out.extend_from_slice(sum(&json).as_bytes());
    out.push(b' ');
    out.extend_from_slice(&json);
    out.push(b'\n');
    if out.len() > MAX_RECORD_BYTES {
        return Err(LedgerError::Invalid(format!(
            "a task ledger record would be {} bytes, more than {MAX_RECORD_BYTES}",
            out.len()
        )));
    }
    Ok(out)
}

/// What one line holds.
enum Parsed {
    Entry(Entry),
    /// A valid line this version cannot read, naming this task.
    Unknown(String),
}

/// Reads one line (without its newline). `None` if it is damaged.
fn parse_line(bytes: &[u8]) -> Option<Parsed> {
    if bytes.len() < SUM_DIGITS + 2 || bytes[SUM_DIGITS] != b' ' {
        return None;
    }
    let (expected, json) = (&bytes[..SUM_DIGITS], &bytes[SUM_DIGITS + 1..]);
    if sum(json).as_bytes() != expected {
        return None;
    }
    if let Ok(entry) = serde_json::from_slice::<Entry>(json) {
        return Some(Parsed::Entry(entry));
    }
    // The sum is right, so this agent wrote it, or a newer version did: an unknown state for the task
    // it names. One that names no task cannot be attributed, so it counts as damage.
    let value: Value = serde_json::from_slice(json).ok()?;
    let id = value.get("task_id")?.as_str()?;
    is_task_id(id).then(|| Parsed::Unknown(id.to_owned()))
}

/// The open ledger. Owned by the task poller's thread.
#[derive(Debug)]
pub struct Ledger {
    dir: PathBuf,
    file: File,
    len: u64,
    /// In order of first appearance.
    tasks: Vec<Task>,
    index: HashMap<String, usize>,
    /// Outcomes of reported tasks, for compaction's `done` lines.
    outcomes: HashMap<String, Outcome>,
    hold_until: Option<u64>,
    poisoned: bool,
    _lock: Lock,
}

impl Ledger {
    /// Opens (or creates) the ledger in `dir`, repairing a torn tail and recording a hold for damage
    /// (see the module documentation), then compacts it if it is due. `now` is the wall clock.
    pub fn open(dir: &Path, now: SystemTime) -> Result<(Self, Recovery), LedgerError> {
        let lock = Lock::file(&dir.join(LOCK_FILE))?.ok_or(LedgerError::Locked)?;
        fsx::remove_stale_temps(dir, LEDGER_FILE)?;
        fsx::remove_stale_temps(dir, RESULT_FILE)?;
        let path = dir.join(LEDGER_FILE);
        let mut recovery = Recovery::default();

        let (good, damage) = match fsx::read_regular(&path, MAX_LEDGER_BYTES, fsx::Symlinks::Refuse)
        {
            Ok(bytes) => scan(&bytes, &mut recovery),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (Vec::new(), None),
            Err(e) => (Vec::new(), Some(format!("it cannot be read ({e})"))),
        };
        let mut good = good;
        if let Some(why) = &damage {
            // Keep what was there for whoever investigates, then start again from what was readable,
            // under a hold.
            fs::rename(&path, dir.join(DAMAGED_FILE))?;
            fsx::sync_dir(dir)?;
            let hold = Entry::Hold {
                until_unix: unix(now) + hold_seconds(),
                why: why.clone(),
                at: rfc3339(now),
            };
            good.push((line(&hold)?, Parsed::Entry(hold)));
            let contents: Vec<u8> = good.iter().flat_map(|(raw, _)| raw.clone()).collect();
            fsx::write_atomic(&path, &contents, FILE_MODE)?;
            recovery.damaged = Some(why.clone());
        } else if recovery.torn_tail {
            let contents: Vec<u8> = good.iter().flat_map(|(raw, _)| raw.clone()).collect();
            fsx::write_atomic(&path, &contents, FILE_MODE)?;
        }

        let existed = fs::symlink_metadata(&path).is_ok();
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(LedgerError::Io(io::Error::other(format!(
                "{} is not a regular file",
                path.display()
            ))));
        }
        if !existed {
            file.sync_all()?;
            fsx::sync_dir(dir)?;
        }
        let mut ledger = Self {
            dir: dir.to_owned(),
            file,
            len: metadata.len(),
            tasks: Vec::new(),
            index: HashMap::new(),
            outcomes: HashMap::new(),
            hold_until: None,
            poisoned: false,
            _lock: lock,
        };
        for (_, parsed) in good {
            ledger.apply(parsed);
        }
        recovery.compacted = ledger.compact_if_due(now)?;
        Ok((ledger, recovery))
    }

    /// The task with this id, if the ledger has it.
    pub fn task(&self, id: &str) -> Option<&Task> {
        self.index.get(id).map(|&i| &self.tasks[i])
    }

    /// Every task not yet reported, oldest first: what reconciliation reports.
    pub fn pending(&self) -> Vec<Task> {
        self.tasks
            .iter()
            .filter(|t| t.state != State::Reported)
            .cloned()
            .collect()
    }

    /// How many task ids the ledger knows.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Size of the file in bytes.
    #[cfg(test)]
    pub fn bytes(&self) -> u64 {
        self.len
    }

    /// Whether a hold is in force at `now`: nothing may be run.
    pub fn held(&self, now: SystemTime) -> bool {
        self.hold_until.is_some_and(|until| unix(now) < until)
    }

    /// When the hold ends, as seconds since the Unix epoch, if there is one in force at `now`.
    pub fn hold_until(&self, now: SystemTime) -> Option<u64> {
        self.hold_until.filter(|_| self.held(now))
    }

    /// Records the delivery of a task, unless its id is already known. A known id is never recorded
    /// again, so it can never be started again.
    pub fn receive(
        &mut self,
        id: &str,
        task_type: &str,
        catalog_version: u32,
        timeout_seconds: u64,
        parameters: &Value,
        now: SystemTime,
    ) -> Result<Receipt, LedgerError> {
        if let Some(task) = self.task(id) {
            return Ok(Receipt::Known(task.state.clone()));
        }
        if !is_task_id(id) {
            return Err(LedgerError::Invalid(
                "the task id is not a lower-case UUID".into(),
            ));
        }
        let size = serde_json::to_vec(parameters).map_or(usize::MAX, |b| b.len());
        if size > MAX_PARAMETERS_BYTES {
            return Err(LedgerError::Invalid(format!(
                "the task's parameters are {size} bytes as JSON, more than {MAX_PARAMETERS_BYTES}"
            )));
        }
        if self.len >= COMPACT_AT_BYTES {
            self.compact_if_due(now)?;
        }
        let entry = Entry::Received {
            task_id: id.to_owned(),
            task_type: task_type.to_owned(),
            catalog_version,
            timeout_seconds,
            parameters: parameters.clone(),
            at: rfc3339(now),
        };
        let bytes = line(&entry)?;
        if self.len + bytes.len() as u64 + RESERVE_BYTES > MAX_LEDGER_BYTES {
            return Err(LedgerError::Full);
        }
        self.append(&bytes)?;
        self.apply(Parsed::Entry(entry));
        Ok(Receipt::New)
    }

    /// Records that `id` is about to run. Only a task just received, never started, may start; this
    /// returns once the record is on disk, and only then may the server be told or anything run.
    pub fn start(&mut self, id: &str, now: SystemTime) -> Result<(), LedgerError> {
        match self.task(id).map(|t| &t.state) {
            Some(State::Received) => {}
            other => {
                return Err(LedgerError::Step(format!(
                    "task {id} cannot start: it is {}",
                    other.map_or("not in the ledger", State::name)
                )));
            }
        }
        if self.held(now) {
            return Err(LedgerError::Step(format!(
                "task {id} cannot start: the ledger is on hold after damage"
            )));
        }
        self.write(Entry::Started {
            task_id: id.to_owned(),
            at: rfc3339(now),
        })
    }

    /// Records the outcome of `id`. `result` is the full body for the result API: it is written to
    /// [`RESULT_FILE`] first, so a crash after this record can still send it ([`Ledger::result`]).
    pub fn finish(
        &mut self,
        id: &str,
        outcome: Outcome,
        reason: Option<&str>,
        result: &Value,
        now: SystemTime,
    ) -> Result<(), LedgerError> {
        match self.task(id).map(|t| &t.state) {
            Some(State::Received | State::Started | State::Unknown) => {}
            other => {
                return Err(LedgerError::Step(format!(
                    "task {id} cannot finish: it is {}",
                    other.map_or("not in the ledger", State::name)
                )));
            }
        }
        if self.poisoned {
            return Err(LedgerError::Poisoned);
        }
        let stored = StoredResult {
            task_id: id.to_owned(),
            body: result.clone(),
        };
        let bytes = serde_json::to_vec(&stored).map_err(io::Error::other)?;
        if bytes.len() as u64 > MAX_RESULT_BYTES {
            return Err(LedgerError::Invalid(format!(
                "the result of task {id} is {} bytes, more than {MAX_RESULT_BYTES}",
                bytes.len()
            )));
        }
        crate::state::write_record(&self.dir, RESULT_FILE, &bytes)?;
        self.write(Entry::Finished {
            task_id: id.to_owned(),
            outcome,
            reason: reason.map(str::to_owned),
            at: rfc3339(now),
        })
    }

    /// The stored result body of `id`, if [`RESULT_FILE`] holds that task's.
    pub fn result(&self, id: &str) -> Option<Value> {
        let bytes = crate::state::read_record(&self.dir, RESULT_FILE, MAX_RESULT_BYTES).ok()??;
        let stored: StoredResult = serde_json::from_slice(&bytes).ok()?;
        (stored.task_id == id).then_some(stored.body)
    }

    /// Records that the server accepted the result of `id` (or, `rejected`, refused it for good), and
    /// removes its stored result.
    pub fn reported(
        &mut self,
        id: &str,
        rejected: bool,
        now: SystemTime,
    ) -> Result<(), LedgerError> {
        match self.task(id).map(|t| &t.state) {
            Some(State::Finished { .. }) => {}
            other => {
                return Err(LedgerError::Step(format!(
                    "task {id} cannot be reported: it is {}",
                    other.map_or("not in the ledger", State::name)
                )));
            }
        }
        self.write(Entry::Reported {
            task_id: id.to_owned(),
            rejected,
            at: rfc3339(now),
        })?;
        if self.result(id).is_some() {
            fs::remove_file(self.dir.join(RESULT_FILE))?;
            fsx::sync_dir(&self.dir)?;
        }
        Ok(())
    }

    fn write(&mut self, entry: Entry) -> Result<(), LedgerError> {
        let bytes = line(&entry)?;
        if self.len + bytes.len() as u64 > MAX_LEDGER_BYTES {
            // Cannot happen for the steps of a task just received: receive left room for them.
            return Err(LedgerError::Full);
        }
        self.append(&bytes)?;
        self.apply(Parsed::Entry(entry));
        Ok(())
    }

    /// Appends one line and flushes it. On failure the ledger is poisoned: what reached the disk is
    /// unknown, and only reopening (which reads the file) can say.
    fn append(&mut self, bytes: &[u8]) -> Result<(), LedgerError> {
        if self.poisoned {
            return Err(LedgerError::Poisoned);
        }
        let file = &mut self.file;
        let written = (|| {
            #[cfg(test)]
            tests::fail_point()?;
            file.write_all(bytes)?;
            file.sync_all()
        })();
        if let Err(e) = written {
            self.poisoned = true;
            // Best effort: cut off a partial line, so the next open does not need to.
            let _ = self.file.set_len(self.len);
            return Err(LedgerError::Io(e));
        }
        self.len += bytes.len() as u64;
        Ok(())
    }

    /// Applies a record to the in-memory view. A record never moves a task back.
    fn apply(&mut self, parsed: Parsed) {
        let (id, state, task_type) = match parsed {
            Parsed::Unknown(id) => (id, State::Unknown, None),
            Parsed::Entry(entry) => match entry {
                Entry::Hold { until_unix, .. } => {
                    self.hold_until =
                        Some(self.hold_until.map_or(until_unix, |u| u.max(until_unix)));
                    return;
                }
                Entry::Received {
                    task_id, task_type, ..
                } => (task_id, State::Received, Some(task_type)),
                Entry::Started { task_id, at } => {
                    let i = self.slot(&task_id);
                    self.tasks[i].started = true;
                    self.tasks[i].started_at.get_or_insert(at);
                    (task_id, State::Started, None)
                }
                Entry::Finished {
                    task_id,
                    outcome,
                    reason,
                    ..
                } => {
                    self.outcomes.insert(task_id.clone(), outcome);
                    (task_id, State::Finished { outcome, reason }, None)
                }
                Entry::Reported { task_id, .. } => (task_id, State::Reported, None),
                Entry::Done {
                    task_id, outcome, ..
                } => {
                    if let Some(outcome) = outcome {
                        self.outcomes.insert(task_id.clone(), outcome);
                    }
                    (task_id, State::Reported, None)
                }
            },
        };
        let i = self.slot(&id);
        let task = &mut self.tasks[i];
        if task.task_type.is_none() {
            task.task_type = task_type;
        }
        if state.rank() > task.state.rank() {
            task.state = state;
        }
    }

    fn slot(&mut self, id: &str) -> usize {
        if let Some(&i) = self.index.get(id) {
            return i;
        }
        self.tasks.push(Task {
            id: id.to_owned(),
            task_type: None,
            state: State::Received,
            started: false,
            started_at: None,
        });
        self.index.insert(id.to_owned(), self.tasks.len() - 1);
        self.tasks.len() - 1
    }

    /// Compacts the file if it is past [`COMPACT_AT_BYTES`] and every task in it is reported.
    fn compact_if_due(&mut self, now: SystemTime) -> Result<bool, LedgerError> {
        if self.len < COMPACT_AT_BYTES || !self.pending().is_empty() {
            return Ok(false);
        }
        self.compact(now)?;
        Ok(true)
    }

    /// Rewrites the file with a `done` line for each of the last [`KEEP_DONE`] tasks (all reported)
    /// and the hold in force, atomically.
    fn compact(&mut self, now: SystemTime) -> Result<(), LedgerError> {
        if self.poisoned {
            return Err(LedgerError::Poisoned);
        }
        let at = rfc3339(now);
        let mut contents = Vec::new();
        if let Some(until_unix) = self.hold_until(now) {
            contents.extend(line(&Entry::Hold {
                until_unix,
                why: "kept by compaction".into(),
                at: at.clone(),
            })?);
        }
        let keep = self.tasks.len().saturating_sub(KEEP_DONE);
        let kept: Vec<Task> = self.tasks[keep..].to_vec();
        for task in &kept {
            contents.extend(line(&Entry::Done {
                task_id: task.id.clone(),
                outcome: self.outcomes.get(&task.id).copied(),
                at: at.clone(),
            })?);
        }
        let path = self.dir.join(LEDGER_FILE);
        fsx::write_atomic(&path, &contents, FILE_MODE)?;
        // The old handle names the replaced file; append to the new one.
        let file = OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path);
        let file = match file {
            Ok(file) => file,
            Err(e) => {
                self.poisoned = true;
                return Err(LedgerError::Io(e));
            }
        };
        self.file = file;
        self.len = contents.len() as u64;
        self.outcomes
            .retain(|id, _| kept.iter().any(|t| &t.id == id));
        self.index = kept
            .iter()
            .enumerate()
            .map(|(i, t)| (t.id.clone(), i))
            .collect();
        self.tasks = kept;
        Ok(())
    }
}

/// [`RESULT_FILE`]'s contents.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredResult {
    task_id: String,
    body: Value,
}

/// Splits the file into lines. Returns each readable line (raw, newline included) and its record,
/// and why the ledger is damaged, if it is. A bad or unterminated last line is a torn tail.
fn scan(bytes: &[u8], recovery: &mut Recovery) -> (Vec<(Vec<u8>, Parsed)>, Option<String>) {
    let mut good = Vec::new();
    let mut pieces: Vec<&[u8]> = bytes.split(|b| *b == b'\n').collect();
    // `split` yields an empty piece after a final newline; anything else there is unterminated.
    let unterminated = pieces.pop().filter(|rest| !rest.is_empty());
    let last = pieces.len();
    let mut damage = None;
    for (n, piece) in pieces.into_iter().enumerate() {
        match parse_line(piece) {
            Some(parsed) => {
                if matches!(parsed, Parsed::Unknown(_)) {
                    recovery.unknown_records += 1;
                }
                let mut raw = piece.to_vec();
                raw.push(b'\n');
                good.push((raw, parsed));
            }
            None if n + 1 == last && unterminated.is_none() => recovery.torn_tail = true,
            None => {
                // Keep reading: every readable record still counts.
                damage.get_or_insert_with(|| {
                    format!("line {} is damaged and later lines follow it", n + 1)
                });
            }
        }
    }
    if let Some(rest) = unterminated {
        // The append that wrote it never returned. If it is whole, keep it: believing a record is the
        // safe side (a `started` kept is reported `interrupted`, never run).
        if let Some(parsed) = parse_line(rest) {
            if matches!(parsed, Parsed::Unknown(_)) {
                recovery.unknown_records += 1;
            }
            let mut raw = rest.to_vec();
            raw.push(b'\n');
            good.push((raw, parsed));
        }
        recovery.torn_tail = true;
    }
    (good, damage)
}

#[cfg(test)]
mod tests;
