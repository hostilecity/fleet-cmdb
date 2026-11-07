//! Configuration facts (FR-2.1, AC-2.1, AC-2.5; P2-A01, P2-A02, P2-A03).
//!
//! [`collect`] takes the server's fact manifest ([`manifest::Manifest`]) and returns one [`Fact`] for
//! every fact in it, so a report never silently leaves one out:
//!
//! - `ok` with a value of the type the manifest gives the fact;
//! - `unreadable` with a reason: the agent knows the fact but could not read it here (the program is
//!   missing, permission was denied, a timeout, output it could not parse, a value the manifest's
//!   limits do not allow);
//! - `unsupported` with a reason: this agent has no reader for the key (a fact added to the manifest
//!   after this agent was built), reads a different type than the manifest now says, or will not look
//!   at the path or unit the manifest names.
//!
//! # The manifest names keys, never commands
//!
//! The agent decides how to read each key it knows, from the table below. The manifest chooses which
//! keys are asked for and, for `file:` and `service:` facts, which path to `stat` and which unit to
//! ask systemd about; it never supplies a program, an argument, or a path to read. A path is only
//! `stat`ed ([`files`]); a unit name is only passed to `systemctl show` after it has passed
//! [`systemd::valid_unit`], after `--` ([`systemd`]); every other command is fixed in the reader.
//! A hostile manifest is also bounded: at most [`manifest::MAX_FACTS`] facts, limits clamped to the
//! agent's own caps, at most [`MAX_FILE_FACTS`] files and [`MAX_UNIT_FACTS`] units looked at, and the
//! whole collection within [`BUDGET`] of command time.
//!
//! # Sources
//!
//! | Facts | Reader | Source |
//! |---|---|---|
//! | `sshd.*` (20) | [`sshd`] | `sshd -T` |
//! | `login_defs.*` (5) | [`policy`] | `/etc/login.defs` |
//! | `useradd.inactive` | [`policy`] | `/etc/default/useradd` |
//! | `pwquality.*` (8) | [`policy`] | `pwquality.conf`, `pwquality.conf.d/*.conf`, the `pam_pwquality.so` line of `/etc/pam.d/common-password` |
//! | `auto_updates.*` (2) | [`updates`] | `/usr/bin/unattended-upgrade`, `apt-config dump`, `systemctl show` of the apt timers |
//! | `firewall.*` (2) | [`firewall`] | `systemctl show` of the firewall units, `/etc/ufw/ufw.conf` |
//! | `services.running`, `services.enabled` | [`systemd`] | `systemctl list-units`, `systemctl list-unit-files` |
//! | `users.*` (3) | [`users`] | `/etc/passwd` |
//! | `file:<path>` | [`files`] | `stat(2)` |
//! | `service:<unit>` | [`systemd`] | `systemctl show` |
//!
//! Each source is read at most once per collection, and only when the manifest has a fact for it.
//! Reading is separate from parsing: the parsers are pure functions over bytes, tested with fixture
//! files in `tests/fixtures/facts/debian13/`.
//!
//! # Values the server accepts
//!
//! The server refuses a whole report for one value outside the manifest's limits, so [`finalize`]
//! checks every value the readers produce against the fact's type and limits (string and entry
//! lengths, list sizes, integer range, no control characters) and turns one that does not fit into
//! `unreadable` with the reason, rather than truncating it (a cut list or path would be a wrong
//! value). Reasons are made safe for a log line and cut to the contract's 512 characters.
//!
//! # Secrets
//!
//! No reader opens a file that holds secrets: [`host::read_file`] refuses them, and the readers do
//! not ask. `/etc/shadow` and `/etc/gshadow` are only `stat`ed; `/etc/passwd` is read for names, ids,
//! homes, and shells; `sshd -T` output is reduced to the listed keywords.

#[cfg(test)]
pub(crate) mod fake;
pub mod files;
pub mod firewall;
pub mod host;
pub mod manifest;
pub mod policy;
pub mod sshd;
pub mod systemd;
pub mod updates;
pub mod users;

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

pub use host::Host;
use host::{Command, RunError, Stat};
use manifest::{FactType, Manifest, ManifestFact};

/// Longest a collection may spend running commands in all. Each command also has its own limit.
pub const BUDGET: Duration = Duration::from_secs(60);
/// The most `file:` facts looked at in one collection; the rest are `unsupported`.
pub const MAX_FILE_FACTS: usize = 512;
/// The most `service:` facts looked at in one collection; the rest are `unsupported`.
pub const MAX_UNIT_FACTS: usize = 512;
/// The longest reason the contract allows.
pub const MAX_REASON_CHARS: usize = 512;

/// What a reader found for one fact, before it is checked against the manifest's limits.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Ok(Value),
    Unreadable(String),
    Unsupported(String),
}

/// A fact's state in a report (`config.request`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Ok,
    Unreadable,
    Unsupported,
}

/// One entry of a report's `facts`: `{state, value, reason}`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Fact {
    pub state: State,
    pub value: Value,
    pub reason: Option<String>,
}

impl Fact {
    fn ok(value: Value) -> Self {
        Self {
            state: State::Ok,
            value,
            reason: None,
        }
    }

    pub(crate) fn unreadable(reason: &str) -> Self {
        Self {
            state: State::Unreadable,
            value: Value::Null,
            reason: Some(clip_reason(reason)),
        }
    }

    fn unsupported(reason: &str) -> Self {
        Self {
            state: State::Unsupported,
            value: Value::Null,
            reason: Some(clip_reason(reason)),
        }
    }
}

/// A reason for the report: control characters become spaces, it is cut to
/// [`MAX_REASON_CHARS`], and it is never empty (the contract requires at least one character).
pub fn clip_reason(reason: &str) -> String {
    let clean = crate::logging::sanitize(reason, MAX_REASON_CHARS);
    let clean = clean.trim();
    if clean.is_empty() {
        "no reason was given".to_owned()
    } else {
        clean.to_owned()
    }
}

/// A sentence for a failed file operation on `path`.
pub fn io_reason(path: &str, error: &io::Error) -> String {
    match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => format!("{path} does not exist"),
        io::ErrorKind::PermissionDenied => format!("permission denied reading {path}"),
        io::ErrorKind::TimedOut => format!("reading {path} timed out: {error}"),
        _ => format!(
            "cannot read {path}: {}",
            crate::logging::sanitize(&error.to_string(), 200)
        ),
    }
}

/// What a reader may use: the host, and the time left for commands.
pub struct Ctx<'a> {
    host: &'a dyn Host,
    deadline: Instant,
}

impl<'a> Ctx<'a> {
    pub fn new(host: &'a dyn Host, budget: Duration) -> Self {
        Self {
            host,
            deadline: Instant::now() + budget,
        }
    }

    /// Runs `command`, shortening its time limit to what is left of the budget.
    pub fn run(&self, mut command: Command) -> Result<Vec<u8>, RunError> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(RunError::OutOfTime);
        }
        command.timeout = command.timeout.min(left);
        self.host.run(&command)
    }

    /// A bounded read; refuses secret files ([`host::is_secret_path`]).
    pub fn read(&self, path: &str, max_bytes: u64) -> io::Result<Vec<u8>> {
        host::read_file(self.host, path, max_bytes)
    }

    pub fn stat(&self, path: &str) -> io::Result<Stat> {
        self.host.stat(std::path::Path::new(path))
    }

    pub fn list(&self, dir: &str, max_entries: usize) -> io::Result<Vec<String>> {
        self.host.list(std::path::Path::new(dir), max_entries)
    }
}

/// The readers that answer a fixed set of manifest keys at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Source {
    Sshd,
    LoginDefs,
    Useradd,
    Pwquality,
    AutoUpdates,
    Firewall,
    Services,
    Users,
}

const SOURCES: [Source; 8] = [
    Source::Sshd,
    Source::LoginDefs,
    Source::Useradd,
    Source::Pwquality,
    Source::AutoUpdates,
    Source::Firewall,
    Source::Services,
    Source::Users,
];

impl Source {
    /// The keys this reader answers, and the type it produces for each.
    fn keys(self) -> Vec<(&'static str, FactType)> {
        match self {
            Self::Sshd => sshd::keys().collect(),
            Self::LoginDefs => policy::login_defs_keys().collect(),
            Self::Useradd => policy::useradd_keys().collect(),
            Self::Pwquality => policy::pwquality_keys().collect(),
            Self::AutoUpdates => updates::KEYS.to_vec(),
            Self::Firewall => firewall::KEYS.to_vec(),
            Self::Services => SERVICE_KEYS.to_vec(),
            Self::Users => users::KEYS.to_vec(),
        }
    }

    fn read(self, ctx: &Ctx) -> HashMap<&'static str, Outcome> {
        match self {
            Self::Sshd => sshd::read(ctx),
            Self::LoginDefs => policy::read_login_defs(ctx),
            Self::Useradd => policy::read_useradd(ctx),
            Self::Pwquality => policy::read_pwquality(ctx),
            Self::AutoUpdates => updates::read(ctx),
            Self::Firewall => firewall::read(ctx),
            Self::Services => read_services(ctx),
            Self::Users => users::read(ctx),
        }
    }
}

const SERVICE_KEYS: &[(&str, FactType)] = &[
    ("services.running", FactType::StringList),
    ("services.enabled", FactType::StringList),
];

fn read_services(ctx: &Ctx) -> HashMap<&'static str, Outcome> {
    let outcome = |listing: Result<Vec<String>, String>| match listing {
        Ok(names) => Outcome::Ok(serde_json::json!(names)),
        Err(reason) => Outcome::Unreadable(reason),
    };
    HashMap::from([
        ("services.running", outcome(systemd::running(ctx))),
        ("services.enabled", outcome(systemd::enabled(ctx))),
    ])
}

/// The keys this agent knows how to read, with their types: every named key of every [`Source`].
/// (`file:` and `service:` facts are read for whatever path or unit the manifest lists.)
#[cfg(test)]
pub fn known_keys() -> BTreeMap<&'static str, FactType> {
    SOURCES.iter().flat_map(|s| s.keys()).collect()
}

/// How a manifest fact is read.
enum Plan {
    Named(Source, FactType),
    File,
    Unit,
    Unknown,
}

fn plan(fact: &ManifestFact, known: &HashMap<&'static str, (Source, FactType)>) -> Plan {
    if fact.key.starts_with("file:") {
        Plan::File
    } else if fact.key.starts_with("service:") {
        Plan::Unit
    } else if let Some((source, ty)) = known.get(fact.key.as_str()) {
        Plan::Named(*source, ty.clone())
    } else {
        Plan::Unknown
    }
}

/// Collects every fact of `manifest`. Runs in a few seconds on a normal host; commands are bounded by
/// [`BUDGET`] and their own limits, filesystem calls by [`host::IO_TIMEOUT`].
pub fn collect(host: &dyn Host, manifest: &Manifest) -> BTreeMap<String, Fact> {
    collect_within(host, manifest, BUDGET)
}

pub fn collect_within(
    host: &dyn Host,
    manifest: &Manifest,
    budget: Duration,
) -> BTreeMap<String, Fact> {
    let ctx = Ctx::new(host, budget);
    let known: HashMap<&'static str, (Source, FactType)> = SOURCES
        .iter()
        .flat_map(|s| s.keys().into_iter().map(move |(k, ty)| (k, (*s, ty))))
        .collect();

    let mut outcomes: HashMap<&str, Outcome> = HashMap::new();
    let mut read: HashMap<Source, HashMap<&'static str, Outcome>> = HashMap::new();
    let mut files: Vec<&ManifestFact> = Vec::new();
    let mut units: Vec<&ManifestFact> = Vec::new();

    for fact in &manifest.facts {
        let outcome = match plan(fact, &known) {
            Plan::Unknown => {
                Outcome::Unsupported("this agent version has no reader for this fact".to_owned())
            }
            Plan::Named(_, ty) if ty != fact.ty => Outcome::Unsupported(format!(
                "the manifest gives this fact the type {}, but this agent version reads {}",
                fact.ty.name(),
                ty.name()
            )),
            Plan::Named(source, _) => {
                let answers = read.entry(source).or_insert_with(|| source.read(&ctx));
                answers.remove(fact.key.as_str()).unwrap_or_else(|| {
                    Outcome::Unreadable("the reader gave no answer for this fact".to_owned())
                })
            }
            Plan::File if fact.ty != FactType::FileAttributes => {
                Outcome::Unsupported(type_mismatch(fact, "file_attributes"))
            }
            Plan::File if files.len() >= MAX_FILE_FACTS => Outcome::Unsupported(format!(
                "the manifest lists more than {MAX_FILE_FACTS} files; this agent looks at the first {MAX_FILE_FACTS}"
            )),
            Plan::File => {
                files.push(fact);
                continue;
            }
            Plan::Unit if fact.ty != FactType::ServiceState => {
                Outcome::Unsupported(type_mismatch(fact, "service_state"))
            }
            Plan::Unit if units.len() >= MAX_UNIT_FACTS => Outcome::Unsupported(format!(
                "the manifest lists more than {MAX_UNIT_FACTS} units; this agent looks at the first {MAX_UNIT_FACTS}"
            )),
            Plan::Unit => {
                units.push(fact);
                continue;
            }
        };
        outcomes.insert(&fact.key, outcome);
    }

    if !files.is_empty() {
        let paths: Vec<&str> = files
            .iter()
            .map(|f| f.key.strip_prefix("file:").unwrap_or(""))
            .collect();
        for (fact, outcome) in files.iter().zip(files::read(&ctx, &paths)) {
            outcomes.insert(&fact.key, outcome);
        }
    }
    if !units.is_empty() {
        read_units(&ctx, &units, &mut outcomes);
    }

    manifest
        .facts
        .iter()
        .map(|fact| {
            let outcome = outcomes
                .remove(fact.key.as_str())
                .unwrap_or_else(|| Outcome::Unreadable("the fact was not read".to_owned()));
            (fact.key.clone(), finalize(fact, outcome))
        })
        .collect()
}

fn type_mismatch(fact: &ManifestFact, expected: &str) -> String {
    format!(
        "the manifest gives this fact the type {}, but this agent version reads {expected}",
        fact.ty.name()
    )
}

/// The state of each unit fact: names that are not unit names are `unsupported`; the rest are asked
/// of systemd in batches.
fn read_units<'a>(ctx: &Ctx, units: &[&'a ManifestFact], outcomes: &mut HashMap<&'a str, Outcome>) {
    let mut valid: Vec<(&'a ManifestFact, &str)> = Vec::new();
    for fact in units {
        let name = fact.key.strip_prefix("service:").unwrap_or("");
        if systemd::valid_unit(name) {
            valid.push((fact, name));
        } else {
            outcomes.insert(
                &fact.key,
                Outcome::Unsupported(
                    "this is not a systemd unit name this agent will pass to systemctl (it must end in .service, .socket, .timer, ...)".to_owned(),
                ),
            );
        }
    }
    if valid.is_empty() {
        return;
    }
    let names: Vec<&str> = valid.iter().map(|(_, name)| *name).collect();
    match systemd::show(ctx, &names) {
        Ok(states) => {
            for ((fact, name), info) in valid.iter().zip(states) {
                outcomes.insert(&fact.key, systemd::state_outcome(name, info.as_ref()));
            }
        }
        Err(reason) => {
            for (fact, _) in valid {
                outcomes.insert(&fact.key, Outcome::Unreadable(reason.clone()));
            }
        }
    }
}

/// Turns a reader's outcome into the fact for the report, checking a value against the manifest's
/// type and limits.
pub fn finalize(fact: &ManifestFact, outcome: Outcome) -> Fact {
    match outcome {
        Outcome::Unsupported(reason) => Fact::unsupported(&reason),
        Outcome::Unreadable(reason) => Fact::unreadable(&reason),
        Outcome::Ok(value) => match check(fact, &value) {
            Ok(()) => Fact::ok(value),
            Err(problem) => Fact::unreadable(&format!(
                "the value does not fit what the manifest allows for this fact: {problem}"
            )),
        },
    }
}

/// Whether `value` is acceptable for `fact`: the server's checks (`ConfigManifest::Fact#value_errors`)
/// and the contract's (`config.request`), including no control characters in any string.
pub fn check(fact: &ManifestFact, value: &Value) -> Result<(), String> {
    let limits = &fact.limits;
    let text_ok = |s: &str, max: usize, what: &str| -> Result<(), String> {
        if s.chars().count() > max {
            return Err(format!("{what} is longer than {max} characters"));
        }
        if s.chars().any(char::is_control) {
            return Err(format!("{what} contains a control character"));
        }
        Ok(())
    };
    match &fact.ty {
        FactType::String => match value {
            Value::String(s) => text_ok(s, limits.max_length, "the value"),
            _ => Err("the value is not a string".into()),
        },
        FactType::Integer => match value.as_i64() {
            Some(n) if (limits.minimum..=limits.maximum).contains(&n) => Ok(()),
            Some(n) => Err(format!(
                "{n} is outside {} to {}",
                limits.minimum, limits.maximum
            )),
            None => Err("the value is not a whole number".into()),
        },
        FactType::Boolean => value
            .is_boolean()
            .then_some(())
            .ok_or_else(|| "the value is not true or false".into()),
        FactType::StringList => {
            let Value::Array(items) = value else {
                return Err("the value is not a list".into());
            };
            if items.len() > limits.max_items {
                return Err(format!(
                    "{} entries, and the manifest allows at most {}",
                    items.len(),
                    limits.max_items
                ));
            }
            for (index, item) in items.iter().enumerate() {
                match item {
                    Value::String(s) => {
                        text_ok(s, limits.item_max_length, &format!("entry {}", index + 1))?
                    }
                    _ => return Err(format!("entry {} is not a string", index + 1)),
                }
            }
            Ok(())
        }
        FactType::FileAttributes => match value {
            Value::Null => Ok(()),
            Value::Object(map) => {
                let mode = map.get("mode").and_then(Value::as_str).unwrap_or("");
                if !(3..=4).contains(&mode.len())
                    || !mode.bytes().all(|b| (b'0'..=b'7').contains(&b))
                {
                    return Err("the mode is not 3 or 4 octal digits".into());
                }
                for name in ["owner", "group"] {
                    let s = map.get(name).and_then(Value::as_str).unwrap_or("");
                    if s.is_empty() {
                        return Err(format!("the {name} is empty"));
                    }
                    text_ok(s, 64, name)?;
                }
                Ok(())
            }
            _ => Err("the value is not null or an object".into()),
        },
        FactType::ServiceState => match value {
            Value::Null => Ok(()),
            Value::Object(map) => {
                for name in ["active", "enabled"] {
                    let s = map.get(name).and_then(Value::as_str).unwrap_or("");
                    let word = s.len() <= 32
                        && s.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                        && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'-');
                    if !word {
                        return Err(format!("{name} is not a lower-case word"));
                    }
                }
                Ok(())
            }
            _ => Err("the value is not null or an object".into()),
        },
        FactType::Unknown(name) => Err(format!("this agent does not know the type {name}")),
    }
}

#[cfg(test)]
mod tests;
