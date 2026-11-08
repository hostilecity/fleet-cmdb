//! The package reporter (FR-2.3, P2-AGENT-PACKAGES, DEC-07).
//!
//! A `packages` report (`POST /api/v1/reports/packages`) lists every installed package
//! ([`crate::packages`]) and names the ones left out (`skipped`: an interrupted installation, or a line
//! the contract cannot carry whose name is readable); or it says `unsupported` (no dpkg, or another
//! manager) or `unreadable` (dpkg is there but cannot be listed) with the reason and no packages. It follows the config report's cadence
//! and handling ([`super::config`]), as FR-2.3 asks:
//!
//! - **on startup**;
//! - **on schedule**, one config-report interval (`[config_report] interval_seconds`, 6 hours by
//!   default, less up to 10% jitter) after the previous report was accepted or rejected;
//! - **on request**: the heartbeat's `report_request` directive names `packages`
//!   ([`Reporter::request`], [`super::requests`]): one extra report per request episode, collected after
//!   the request.
//!
//! Each report gets a new `report_id`. A failed send is retried with the **same** report id and body
//! ([`crate::retry`]); while one waits for its retry, a request or its being one interval old replaces it
//! with a fresh listing. A report rejected for its content (`400`, `413`, `422`) is not retried.
//!
//! **Compression and size.** The body is sent with `Content-Encoding: gzip` (P2-S08). It is serialized
//! straight into the encoder, so the JSON is never held whole, and only the compressed bytes are kept for
//! a retry (about 30 KiB for 3,000 packages). The server takes at most 4 MiB of JSON and 1 MiB
//! compressed; a list that does not fit within [`MAX_JSON_BYTES`] and [`MAX_GZIP_BYTES`] is not sent in
//! part: the report says `unreadable` with the reason, so the server keeps an unknown set rather than
//! a smaller one.
//!
//! **Stopping.** With [`Reporter::stopping_on`], a stop request ends a tick after what is in flight: the
//! listing is not started, a listing that finishes meanwhile is dropped (not sent, not kept), and no
//! send starts. So stopping waits for at most the listing ([`crate::packages::TIMEOUT`], 20 s) or one
//! request (30 s).

use std::io::{self, Write};
use std::time::{Duration, Instant, SystemTime};

use flate2::Compression;
use flate2::write::GzEncoder;
use serde::Serialize;
use serde_json::Value;

use super::config::rejected_for_content;
use super::time::rfc3339;
use super::{Transport, new_report_id};
use crate::client::ApiError;
use crate::facts::host::Host;
use crate::packages::{self, Collected, Listing, Package, Skipped};
use crate::retry::{Backoff, Rng};
use crate::shutdown::Shutdown;
use crate::{AGENT_SCHEMA_VERSION, AGENT_VERSION};

pub const PACKAGES_PATH: &str = "/api/v1/reports/packages";

/// The most JSON a report may be before compression: the server reads 4 MiB; this leaves room.
pub const MAX_JSON_BYTES: usize = 4_000_000;
/// The most a compressed report may be: the server takes 1 MiB on the wire; this leaves room.
pub const MAX_GZIP_BYTES: usize = 1_000_000;

/// How long to wait before building again after a report could not be built at all.
const HOLD: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Startup,
    Scheduled,
    Requested,
}

impl Reason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Scheduled => "scheduled",
            Self::Requested => "requested",
        }
    }
}

struct Pending {
    report_id: String,
    /// The gzip-compressed body, sent again as it is on a retry.
    body: Vec<u8>,
    reason: Reason,
    built_at: Instant,
}

pub struct Reporter<'a, R: Rng> {
    host: &'a dyn Host,
    interval: Duration,
    backoff: Backoff<R>,
    rng: R,
    pending: Option<Pending>,
    retry_at: Option<Instant>,
    last_done: Option<Instant>,
    jitter_permille: u32,
    hold_until: Option<Instant>,
    /// A report is wanted now, and why.
    wanted: Option<Reason>,
    /// A report built for a request was accepted ([`Reporter::take_answered`]).
    answered: bool,
    /// Once requested, nothing new starts: no listing, no send ([`Reporter::stopping_on`]).
    stop: Option<&'a Shutdown>,
    new_id: fn() -> io::Result<String>,
    /// The real time the current tick began, so a delay after a failure counts from the failure, not
    /// from the tick's (simulated) `now` ([`super::failed_at`], review of #117).
    tick_started: Instant,
}

impl<'a, R: Rng> Reporter<'a, R> {
    pub fn new(host: &'a dyn Host, interval: Duration, backoff: Backoff<R>, rng: R) -> Self {
        Self {
            host,
            interval,
            backoff,
            rng,
            pending: None,
            retry_at: None,
            last_done: None,
            jitter_permille: 0,
            hold_until: None,
            wanted: None,
            answered: false,
            stop: None,
            new_id: new_report_id,
            tick_started: Instant::now(),
        }
    }

    /// Stops starting work once `stop` is requested: the listing is not run, a listing that finishes
    /// meanwhile is dropped rather than sent, and nothing is sent after that.
    pub fn stopping_on(mut self, stop: &'a Shutdown) -> Self {
        self.stop = Some(stop);
        self
    }

    fn stopping(&self) -> bool {
        self.stop.is_some_and(Shutdown::is_requested)
    }

    /// Asks for one extra report at the next [`Reporter::tick`].
    pub fn request(&mut self) {
        self.wanted = Some(Reason::Requested);
    }

    /// Whether a report built for a request has been accepted since the last call
    /// ([`super::requests::ReportRequests::answered`]).
    pub fn take_answered(&mut self) -> bool {
        std::mem::take(&mut self.answered)
    }

    #[cfg(test)]
    pub fn pending_report_id(&self) -> Option<&str> {
        self.pending.as_ref().map(|p| p.report_id.as_str())
    }

    /// Does whatever is due at `now` and returns when to call again.
    pub fn tick(&mut self, now: Instant, transport: &dyn Transport) -> Instant {
        self.tick_started = Instant::now();
        let held = self.hold_until.is_some_and(|hold| now < hold);
        if self.wanted.is_some() && !held {
            let reason = self.wanted.take().unwrap_or(Reason::Requested);
            self.build(reason, now);
        } else if now >= self.build_due_at(now) {
            let reason = match &self.pending {
                Some(pending) => pending.reason,
                None if self.last_done.is_none() => Reason::Startup,
                None => Reason::Scheduled,
            };
            self.build(reason, now);
        }

        if self.pending.is_some() && self.retry_at.is_none_or(|at| now >= at) {
            self.send(transport, now);
        }

        let mut wake = self.build_due_at(now);
        if self.pending.is_some()
            && let Some(at) = self.retry_at
        {
            wake = wake.min(at);
        }
        if self.wanted.is_some() {
            wake = self.hold_until.map_or(now, |hold| hold.max(now));
        }
        wake
    }

    fn build_due_at(&self, now: Instant) -> Instant {
        let due = match (&self.pending, self.last_done) {
            (Some(pending), _) => pending.built_at + self.interval,
            (None, Some(done)) => {
                done + self.interval - self.interval * self.jitter_permille / 1000
            }
            (None, None) => now,
        };
        self.hold_until.map_or(due, |hold| due.max(hold))
    }

    /// Lists the packages and builds a report with a new id, replacing any report still waiting.
    fn build(&mut self, reason: Reason, now: Instant) {
        if self.stopping() {
            return;
        }
        let report_id = match (self.new_id)() {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(
                    "cannot generate a report id ({e}); the package report is postponed"
                );
                self.hold_until = Some(now + HOLD);
                if reason == Reason::Requested {
                    self.wanted = Some(reason);
                }
                return;
            }
        };
        let collected_at = rfc3339(SystemTime::now());
        let collected = packages::collect(self.host, self.stop);
        if self.stopping() || collected == Collected::Stopping {
            tracing::info!(
                reason = reason.as_str(),
                "the agent is stopping; the package list is not sent"
            );
            return;
        }
        let encoded = encode(&report_id, &collected_at, &collected);
        self.hold_until = None;
        self.retry_at = None;
        let span = tracing::info_span!("package_report", report_id = report_id.as_str());
        let _entered = span.enter();
        let replaced = self.pending.as_ref().map_or("", |p| p.report_id.as_str());
        match (&collected, &encoded.refused) {
            (Collected::Dpkg(listing), None) => tracing::info!(
                reason = reason.as_str(),
                manager = "dpkg",
                packages = listing.packages.len(),
                skipped = listing.skipped.len(),
                skipped_not_named = listing.skipped_not_named,
                not_configured = listing.not_configured,
                removed = listing.removed,
                warnings = listing.warnings.len(),
                json_bytes = encoded.json_bytes,
                gzip_bytes = encoded.body.len(),
                replaced,
                "listed the installed packages"
            ),
            (Collected::Dpkg(_), Some(why)) | (Collected::Unreadable(why), _) => tracing::warn!(
                reason = reason.as_str(),
                manager = "unreadable",
                unsupported_reason = why.as_str(),
                replaced,
                "dpkg is here but its packages cannot be reported; the report says why"
            ),
            (Collected::Unsupported(why), _) => tracing::warn!(
                reason = reason.as_str(),
                manager = "unsupported",
                unsupported_reason = why.as_str(),
                replaced,
                "the installed packages cannot be reported; the report says why"
            ),
            (Collected::Stopping, _) => {}
        }
        if let Collected::Dpkg(listing) = &collected {
            for warning in &listing.warnings {
                tracing::warn!(warning = warning.as_str(), "package list");
            }
            for skipped in &listing.skipped {
                tracing::warn!(
                    package = skipped.name.as_str(),
                    reason = skipped.reason.as_str(),
                    "package skipped: not reported as installed"
                );
            }
        }
        self.pending = Some(Pending {
            report_id,
            body: encoded.body,
            reason,
            built_at: now,
        });
    }

    fn send(&mut self, transport: &dyn Transport, now: Instant) {
        if self.stopping() {
            return;
        }
        let Some(pending) = self.pending.as_ref() else {
            return;
        };
        let span = tracing::info_span!("package_report", report_id = pending.report_id.as_str());
        let _entered = span.enter();
        let reason = pending.reason.as_str();
        let requested = pending.reason == Reason::Requested;
        let attempt = self.backoff.failures() + 1;
        match transport.post_gzip(PACKAGES_PATH, &pending.body) {
            Ok(response) => {
                let request_id = response.request_id.as_deref().unwrap_or("");
                let duplicate = response.body.get("duplicate").and_then(Value::as_bool);
                if response.body.get("report_id").and_then(Value::as_str)
                    != Some(pending.report_id.as_str())
                {
                    tracing::warn!(
                        request_id,
                        "the server's reply does not name this report; treating it as accepted"
                    );
                }
                tracing::info!(
                    reason,
                    attempt,
                    request_id,
                    duplicate = duplicate == Some(true),
                    "package report sent"
                );
                self.answered |= requested;
                self.finished(now);
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
                    "the server rejected the package report; it will not be retried, and the next report follows the normal schedule"
                );
                self.finished(now);
            }
            Err(error) => {
                // The listing and the request took real time: the backoff starts now, not at `now`.
                let failed = super::failed_at(now, self.tick_started);
                self.retry_at = Some(failed + self.backoff.on_failure(&error));
            }
        }
    }

    fn finished(&mut self, now: Instant) {
        self.pending = None;
        self.retry_at = None;
        self.backoff.on_success();
        self.last_done = Some(now);
        self.jitter_permille = (self.rng.next_u64() % 101) as u32; // 0..=100 fits
    }
}

/// A report body, compressed.
pub struct Encoded {
    pub body: Vec<u8>,
    /// Bytes of JSON before compression.
    pub json_bytes: usize,
    /// Why a dpkg listing was sent as `unreadable` instead: it did not fit.
    pub refused: Option<String>,
}

#[derive(Serialize)]
struct Body<'a> {
    schema_version: u32,
    agent_version: &'a str,
    report_id: &'a str,
    collected_at: &'a str,
    manager: &'static str,
    unsupported_reason: Option<&'a str>,
    packages: &'a [Package],
    /// Left out when empty: absent means none (the contract), and a server that predates it is unchanged.
    #[serde(skip_serializing_if = "<[Skipped]>::is_empty")]
    skipped: &'a [Skipped],
    warnings: Vec<Warning<'a>>,
}

#[derive(Serialize)]
struct Warning<'a> {
    field: &'static str,
    message: &'a str,
}

/// The gzip-compressed `packages.request` body. A dpkg listing too large for the server's limits
/// becomes an `unreadable` report saying so ([`Encoded::refused`]).
pub fn encode(report_id: &str, collected_at: &str, collected: &Collected) -> Encoded {
    let empty = Listing::default();
    let without_packages = |manager: &'static str, reason: &str| {
        let reason = crate::facts::clip_reason(reason);
        let body = Body::new(report_id, collected_at, Some((manager, &reason)), &empty);
        // An empty report is a few hundred bytes, far inside both limits.
        compress(&body).unwrap_or_default()
    };
    let (body, json_bytes) = match collected {
        Collected::Dpkg(listing) => {
            match compress(&Body::new(report_id, collected_at, None, listing)) {
                Ok(done) => done,
                Err(why) => {
                    let (body, json_bytes) = without_packages("unreadable", &why);
                    return Encoded {
                        body,
                        json_bytes,
                        refused: Some(crate::facts::clip_reason(&why)),
                    };
                }
            }
        }
        Collected::Unsupported(reason) => without_packages("unsupported", reason),
        Collected::Unreadable(reason) => without_packages("unreadable", reason),
        Collected::Stopping => without_packages("unsupported", "the agent is stopping"),
    };
    Encoded {
        body,
        json_bytes,
        refused: None,
    }
}

impl<'a> Body<'a> {
    /// `without` is the manager and the reason of a report with no packages (`unsupported` or
    /// `unreadable`); `None` is a dpkg listing, whose packages, skipped names, and warnings are sent.
    fn new(
        report_id: &'a str,
        collected_at: &'a str,
        without: Option<(&'static str, &'a str)>,
        listing: &'a Listing,
    ) -> Self {
        let dpkg = without.is_none();
        Self {
            schema_version: AGENT_SCHEMA_VERSION,
            agent_version: AGENT_VERSION,
            report_id,
            collected_at,
            manager: without.map_or("dpkg", |(manager, _)| manager),
            unsupported_reason: without.map(|(_, reason)| reason),
            packages: if dpkg { &listing.packages } else { &[] },
            skipped: if dpkg { &listing.skipped } else { &[] },
            warnings: if dpkg {
                listing
                    .warnings
                    .iter()
                    .map(|message| Warning {
                        field: "packages",
                        message,
                    })
                    .collect()
            } else {
                Vec::new()
            },
        }
    }
}

/// Serializes `body` into a gzip encoder, never holding the JSON whole. Returns the compressed bytes
/// and the JSON's length, or why it is over [`MAX_JSON_BYTES`] or [`MAX_GZIP_BYTES`].
fn compress(body: &Body) -> Result<(Vec<u8>, usize), String> {
    let mut writer = Limited {
        inner: GzEncoder::new(Vec::new(), Compression::default()),
        written: 0,
        limit: MAX_JSON_BYTES,
    };
    if serde_json::to_writer(&mut writer, body).is_err() {
        return Err(format!(
            "the list of {} installed packages is more than the {MAX_JSON_BYTES} bytes of JSON a package report may carry; the list is not sent in part",
            body.packages.len()
        ));
    }
    let json_bytes = writer.written;
    let compressed = writer
        .inner
        .finish()
        .map_err(|e| format!("cannot compress the package report: {e}"))?;
    if compressed.len() > MAX_GZIP_BYTES {
        return Err(format!(
            "the list of {} installed packages compresses to {} bytes, more than the {MAX_GZIP_BYTES} a package report may be; the list is not sent in part",
            body.packages.len(),
            compressed.len()
        ));
    }
    Ok((compressed, json_bytes))
}

/// A writer that fails once more than `limit` bytes would have been written to it, so an oversized
/// report stops being serialized at the limit.
struct Limited<W> {
    inner: W,
    written: usize,
    limit: usize,
}

impl<W: Write> Write for Limited<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written + buf.len() > self.limit {
            return Err(io::Error::other("over the size limit"));
        }
        let n = self.inner.write(buf)?;
        self.written += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests;
