//! Installed packages (FR-2.3, AC-2.3, P2-AGENT-PACKAGES): what the package report lists.
//!
//! [`collect`] detects the package manager and lists every installed package with its name, full
//! version (with any epoch), architecture, and source package. Only dpkg is supported
//! ([DEC-01](../../docs/decisions/0001-fleet-profile.md)). A host the agent cannot list is never an empty
//! list, so the server cannot mistake it for a host with no packages: [`Collected::Unsupported`] (no
//! dpkg, or another manager) and [`Collected::Unreadable`] (dpkg is there but cannot be listed) both
//! carry a reason.
//!
//! # Detection
//!
//! dpkg is the manager when its database (`/var/lib/dpkg/status`) exists and `/usr/bin/dpkg-query`
//! lists it. Without the database the reason names the manager found instead (`rpm`, `apk`), if any.
//!
//! # The listing
//!
//! One command, [`LIST`]: `dpkg-query --show` with a fixed `--showformat` of five tab-separated fields
//! per line (`${db:Status-Status}`, `${Package}`, `${Architecture}`, `${Version}`,
//! `${source:Package}`), run through [`Ctx`] (absolute path, no shell, cleared environment, time limit,
//! output cap, not started once the agent is stopping). None of the fields can contain a tab or a
//! newline: dpkg refuses such names, versions, and architectures. `${source:Package}` is dpkg's own
//! reading of the `Source` field without its `(version)`, falling back to the package name.
//!
//! # Which packages count as installed
//!
//! A package whose status is `installed`, `triggers-awaited`, or `triggers-pending` is reported as
//! installed: in the two trigger states it is unpacked and configured, only a trigger it awaits or owns
//! has not run yet, and apt and `dpkg -l` count it as installed (review of #121). A package in an
//! interrupted installation (`unpacked`, `half-installed`, `half-configured`, owner decision, P2-S08)
//! is not: its name and the status go in [`Listing::skipped`]
//! (and the count in [`Listing::not_configured`]), so the server shows it as skipped, not as installed
//! and not as removed. `config-files` (removed, only its configuration files left) is left out, as
//! `not-installed` already is by `--show`. The selection state (`hold`, `deinstall`) is not part of
//! `${db:Status-Status}`: a held package is `installed` and is reported. The reference listing for
//! AC-2.3 is therefore the lines of `dpkg-query --show` whose status is `installed` or a trigger
//! state, and the interrupted ones are the `skipped` names.
//!
//! # What does not fit the contract
//!
//! The server refuses a whole report for one value outside `packages.request`, so each line is checked
//! here ([`parse`]), never cut to fit:
//!
//! - a line that is not five fields, is not UTF-8, or whose name the contract does not allow, is left
//!   out with a warning (no name can be given);
//! - a line whose name is readable but whose status dpkg does not define, or whose version or
//!   architecture the contract does not allow, is left out with a warning **and** named in
//!   [`Listing::skipped`] with the reason (owner decision);
//! - a source package name the contract does not allow is reported as `null` with a warning;
//! - a name and architecture listed twice keeps the first, with a warning.
//!
//! At most [`MAX_WARNINGS`] warnings are kept, the last one counting the rest, and at most
//! [`MAX_SKIPPED`] names (each name once, whatever its architectures); the skipped names beyond that are
//! counted in one more warning. A host with dpkg whose listing cannot be had at all (the command fails,
//! times out, or prints more than the cap; the database cannot be read) or is over [`MAX_PACKAGES`]
//! packages is not sent in part: the report says `unreadable` with the reason (an unknown set, not a
//! smaller one).
//!
//! # Memory
//!
//! The command's output is held once (at most [`MAX_OUTPUT`]) and parsed line by line in place into
//! [`Package`]s; the output is dropped before the report is encoded, and the report is serialized
//! straight into the gzip encoder ([`crate::report`]), so the JSON is never held whole. Measured peak
//! for 3,000 packages: see `docs/operations/agent-packages.md`.

use std::collections::HashSet;
use std::io;
use std::time::Duration;

use serde::Serialize;

use crate::facts::Ctx;
use crate::facts::host::{Command, Host, RunError};
use crate::shutdown::Shutdown;

/// dpkg's status database.
pub const DPKG_STATUS: &str = "/var/lib/dpkg/status";
/// The query program. Debian ships it in `dpkg`, which is essential, so every Debian host has it.
pub const DPKG_QUERY: &[&str] = &["/usr/bin/dpkg-query"];
/// The fixed arguments of the listing: the fields in [`parse`]'s order.
pub const LIST: &[&str] = &[
    "--show",
    "--showformat=${db:Status-Status}\\t${Package}\\t${Architecture}\\t${Version}\\t${source:Package}\\n",
];
/// Time limit for the listing: a few thousand packages take well under a second.
pub const TIMEOUT: Duration = Duration::from_secs(20);
/// Most bytes of listing kept; a host with this much is over [`MAX_PACKAGES`] anyway (a typical line is
/// 60 to 90 bytes).
pub const MAX_OUTPUT: usize = 8 * 1024 * 1024;
/// The contract's limit on `packages`.
pub const MAX_PACKAGES: usize = 20_000;
/// The contract's limit on `warnings`.
pub const MAX_WARNINGS: usize = 64;
/// The contract's limit on `skipped`.
pub const MAX_SKIPPED: usize = 64;

/// Other package managers, named in the reason when there is no dpkg database.
const OTHER_MANAGERS: &[(&str, &str)] = &[
    ("rpm", "/usr/bin/rpm"),
    ("apk", "/sbin/apk"),
    ("pacman", "/usr/bin/pacman"),
];

/// One installed package, as the contract's `packages` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub architecture: String,
    /// `None` only when dpkg's source name is one the contract does not allow (with a warning).
    pub source: Option<String>,
}

/// A package the agent read the name of but did not list as installed, as the contract's `skipped` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    pub name: String,
    /// Short, at most 128 characters: the dpkg status, or what the contract could not carry.
    pub reason: String,
}

/// The dpkg listing, checked against the contract.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Listing {
    /// Sorted by name, then architecture; each pair once.
    pub packages: Vec<Package>,
    /// For the report's `warnings` (field `packages`): at most [`MAX_WARNINGS`].
    pub warnings: Vec<String>,
    /// For the report's `skipped`: sorted by name, each name once, at most [`MAX_SKIPPED`].
    pub skipped: Vec<Skipped>,
    /// Skipped names beyond [`MAX_SKIPPED`], counted in a warning instead.
    pub skipped_not_named: usize,
    /// Lines in an interrupted installation (`unpacked`, `half-installed`, `half-configured`).
    pub not_configured: usize,
    /// Lines left out because the package is removed (`config-files`).
    pub removed: usize,
}

/// What [`collect`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Collected {
    Dpkg(Listing),
    /// No supported manager (no dpkg database, or another manager): why, for the operator.
    Unsupported(String),
    /// dpkg is there but its packages could not be listed (the database cannot be read, the command
    /// failed, timed out, or printed too much, or the list is too large to send whole): why.
    Unreadable(String),
    /// The agent is stopping, so the listing was not run (or not finished); nothing is to be sent.
    Stopping,
}

/// Detects the manager and lists the packages. Nothing starts once `stop` is requested.
pub fn collect(host: &dyn Host, stop: Option<&Shutdown>) -> Collected {
    let mut ctx = Ctx::new(host, TIMEOUT);
    if let Some(stop) = stop {
        ctx = ctx.stopping_on(stop);
    }
    collect_with(&ctx, stop)
}

fn collect_with(ctx: &Ctx, stop: Option<&Shutdown>) -> Collected {
    let stopping = || stop.is_some_and(Shutdown::is_requested);
    match ctx.stat(DPKG_STATUS) {
        Ok(_) => {}
        Err(_) if stopping() => return Collected::Stopping,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return Collected::Unsupported(no_dpkg_reason(ctx));
        }
        Err(e) => return Collected::Unreadable(crate::facts::io_reason(DPKG_STATUS, &e)),
    }
    let mut command = Command::new(DPKG_QUERY, LIST);
    command.timeout = TIMEOUT;
    command.max_output = MAX_OUTPUT;
    let output = match ctx.run(command) {
        Ok(output) => output,
        Err(RunError::Stopping) => return Collected::Stopping,
        Err(_) if stopping() => return Collected::Stopping,
        Err(e) => return Collected::Unreadable(e.reason("dpkg-query --show")),
    };
    let listing = parse(&output);
    drop(output);
    if listing.packages.len() > MAX_PACKAGES {
        return Collected::Unreadable(too_many(listing.packages.len()));
    }
    Collected::Dpkg(listing)
}

/// The reason for a host without a dpkg database, naming another manager if one is there.
fn no_dpkg_reason(ctx: &Ctx) -> String {
    let found: Vec<&str> = OTHER_MANAGERS
        .iter()
        .filter(|(_, path)| ctx.stat(path).is_ok())
        .map(|(name, _)| *name)
        .collect();
    let base = format!("no dpkg database at {DPKG_STATUS}");
    match found.as_slice() {
        [] => format!("{base}; only dpkg is supported (DEC-01)"),
        [one] => format!("{base}; {one} was found, which is not supported (only dpkg is, DEC-01)"),
        many => format!(
            "{base}; {} were found, which are not supported (only dpkg is, DEC-01)",
            many.join(" and ")
        ),
    }
}

pub fn too_many(count: usize) -> String {
    format!(
        "this host has {count} installed packages, more than the {MAX_PACKAGES} a package report may list; the list is not sent in part"
    )
}

/// Parses the output of [`LIST`]: a pure function, so it is tested on fixtures.
pub fn parse(output: &[u8]) -> Listing {
    // One package per line at most, so the list is allocated once, not doubled as it grows; but no more
    // than a report may carry (and one over, which makes it too many), since removed packages and
    // skipped lines must not size it (review of #117).
    let lines = output.iter().filter(|b| **b == b'\n').count() + 1;
    let mut listing = Listing {
        packages: Vec::with_capacity(lines.min(MAX_PACKAGES + 1)),
        ..Listing::default()
    };
    let mut problems = Problems::default();
    let mut skips = Skips::default();
    for (index, line) in output.split(|b| *b == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let number = index + 1;
        let Ok(text) = std::str::from_utf8(line) else {
            problems.push(format!(
                "line {number} of the dpkg-query output is not UTF-8; skipped"
            ));
            continue;
        };
        let fields: Vec<&str> = text.split('\t').collect();
        let [status, name, architecture, version, source] = fields[..] else {
            problems.push(format!(
                "line {number} of the dpkg-query output has {} fields, not 5; skipped: {}",
                fields.len(),
                quote(text)
            ));
            continue;
        };
        match status {
            // A pending or awaited trigger does not make a configured package less installed.
            "installed" | "triggers-awaited" | "triggers-pending" => {}
            "unpacked" | "half-configured" | "half-installed" => {
                // Not installed in full: named, not listed (the line is not checked further).
                listing.not_configured += 1;
                if valid_name(name) {
                    skips.add(name, status);
                } else {
                    problems.push(bad_name(name));
                }
                continue;
            }
            "config-files" => {
                listing.removed += 1;
                continue;
            }
            "not-installed" => continue,
            other => {
                problems.push(format!(
                    "package {} has the dpkg status {}, which this agent does not know; skipped",
                    quote(name),
                    quote(other)
                ));
                if valid_name(name) {
                    skips.add(name, "dpkg status not known to this agent");
                }
                continue;
            }
        }
        if !valid_name(name) {
            problems.push(bad_name(name));
            continue;
        }
        if !valid_architecture(architecture) {
            skips.add(name, "architecture is not one a package report can carry");
            problems.push(format!(
                "package {name} has the architecture {}, which a package report cannot carry; skipped",
                quote(architecture)
            ));
            continue;
        }
        if !valid_version(version) {
            skips.add(name, "version is not one a package report can carry");
            problems.push(format!(
                "package {name}:{architecture} has the version {}, which a package report cannot carry; skipped",
                quote(version)
            ));
            continue;
        }
        let source = if valid_name(source) {
            Some(source.to_owned())
        } else {
            problems.push(format!(
                "package {name}:{architecture} has the source package name {}, which a package report cannot carry; reported without a source",
                quote(source)
            ));
            None
        };
        listing.packages.push(Package {
            name: name.to_owned(),
            version: version.to_owned(),
            architecture: architecture.to_owned(),
            source,
        });
    }
    // dpkg lists by name and architecture already; sorting makes duplicates adjacent whatever the order.
    listing.packages.sort_by(|a, b| {
        (a.name.as_str(), a.architecture.as_str()).cmp(&(b.name.as_str(), b.architecture.as_str()))
    });
    // In place, so the list is never held twice. `later` is dropped when it repeats `kept`.
    listing.packages.dedup_by(|later, kept| {
        let repeated = later.name == kept.name && later.architecture == kept.architecture;
        if repeated {
            problems.push(format!(
                "package {}:{} is listed more than once; the first is reported",
                later.name, later.architecture
            ));
        }
        repeated
    });
    // What skipped lines left unused is not carried through the report's encoding.
    listing.packages.shrink_to_fit();
    listing.skipped = skips.named;
    listing.skipped.sort_by(|a, b| a.name.cmp(&b.name));
    listing.skipped_not_named = skips.over.len();
    listing.warnings = problems.finish(skips.over.len());
    listing
}

/// Warning messages, at most [`MAX_WARNINGS`]: with more, the last one says how many are not listed.
#[derive(Default)]
struct Problems {
    kept: Vec<String>,
    more: usize,
}

impl Problems {
    fn push(&mut self, message: String) {
        if self.kept.len() < MAX_WARNINGS {
            self.kept.push(crate::facts::clip_reason(&message));
        } else {
            self.more += 1;
        }
    }

    /// `not_named` skipped packages have no entry in `skipped`; one final warning says so, and keeps its
    /// place whatever else is over the limit.
    fn finish(self, not_named: usize) -> Vec<String> {
        let (mut kept, more) = (self.kept, self.more);
        let room = MAX_WARNINGS - usize::from(not_named > 0);
        let total = kept.len() + more;
        if total > room {
            // The count takes the last free place, so one message fewer is kept; it counts that one too.
            kept.truncate(room - 1);
            kept.push(format!(
                "{} more problems with the dpkg-query output are not listed",
                total - (room - 1)
            ));
        }
        if not_named > 0 {
            kept.push(format!(
                "{not_named} more packages were skipped; their names are not listed (at most {MAX_SKIPPED} are)"
            ));
        }
        kept
    }
}

/// Packages named in `skipped`: the first [`MAX_SKIPPED`] names, each once; the rest are only counted.
#[derive(Default)]
struct Skips {
    named: Vec<Skipped>,
    over: HashSet<String>,
}

impl Skips {
    fn add(&mut self, name: &str, reason: &str) {
        if self.named.iter().any(|s| s.name == name) || self.over.contains(name) {
            return;
        }
        if self.named.len() < MAX_SKIPPED {
            self.named.push(Skipped {
                name: name.to_owned(),
                reason: reason.chars().take(128).collect(),
            });
        } else {
            self.over.insert(name.to_owned());
        }
    }
}

fn bad_name(name: &str) -> String {
    format!(
        "package name {} is not one a package report can carry; skipped",
        quote(name)
    )
}

/// A value from the output for a warning: control characters removed, at most 100 characters.
fn quote(value: &str) -> String {
    format!("`{}`", crate::logging::sanitize(value, 100))
}

/// `^[a-z0-9][a-z0-9+._-]{0,127}$`: the contract's binary and source package names.
pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+._-".contains(b))
}

/// `^[a-z0-9][a-z0-9-]{0,31}$`.
pub fn valid_architecture(architecture: &str) -> bool {
    let bytes = architecture.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 32
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// `^[!-~]+$`, at most 256 characters: printable ASCII without spaces. dpkg's own rules are not
/// applied here (the server marks a version dpkg cannot compare as not evaluated, P2-S09).
pub fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 256
        && version.bytes().all(|b| (b'!'..=b'~').contains(&b))
}

#[cfg(test)]
pub(crate) mod tests;
