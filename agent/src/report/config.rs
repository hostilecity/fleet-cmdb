//! The configuration reporter (FR-2.1, P2-A01, DEC-13).
//!
//! A `config` report carries the facts the server's manifest names (`GET /api/v1/manifest/config`).
//! The manifest is data: the agent reads the facts it has a reader for ([`crate::facts`]) and runs
//! nothing the manifest says. A report is sent:
//!
//! - **on startup**, so a fresh agent has facts at once;
//! - **on schedule**, one config-report interval (6 hours by default, less up to 10% jitter) after the
//!   previous report was accepted or rejected;
//! - **on request**: the heartbeat's `report_request` directive names `config`
//!   ([`Reporter::request`], [`super::requests`]): one extra report, collected after the request;
//! - **on a newer manifest**: the server's answer carries its `manifest_version`. When that is above the
//!   version the report used, the manifest is fetched again (conditionally), and only if the fetched
//!   version really is newer is a report built from it at once, so the server is never left holding
//!   facts for an old manifest. A server whose answer stays ahead of its manifest endpoint cannot make
//!   the agent loop: nothing is rebuilt unless the fetched version rose.
//!
//! The manifest is fetched with its `ETag` before every report; a `304` keeps the cached copy. If the
//! fetch fails the cached copy is used (with a warning), and with none the report waits for the retry
//! policy ([`crate::retry`]).
//!
//! Each report gets a new `report_id`. A failed send is retried with the **same** report id and body, so
//! the server can discard a duplicate; no report is queued. While one waits for its retry, a request, a
//! newer manifest, or its being one interval old replaces it with fresh state. A report rejected for its
//! content (`400`, `413`, `422`) is not retried: the same body would be rejected again.
//!
//! The body is kept under [`MAX_BODY_BYTES`] (the server's request limit is 1 MiB on the wire and the
//! agent has no compression): the largest list facts become `unreadable` with a reason until it fits.
//!
//! **Stopping.** With [`Reporter::stopping_on`], a stop request ends a tick after what is in flight:
//! the collection starts no further command or filesystem call, a report collected meanwhile is
//! dropped (not sent, not kept), and no manifest fetch or send starts. An unsent report is simply
//! lost; the next start sends a startup report.

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime};

use serde_json::{Value, json};

use super::time::rfc3339;
use super::{Transport, new_report_id};
use crate::client::{ApiError, Conditional};
use crate::facts::host::Host;
use crate::facts::manifest::{self, Manifest};
use crate::facts::{self, Fact, State};
use crate::retry::{Backoff, Rng};
use crate::shutdown::Shutdown;
use crate::{AGENT_SCHEMA_VERSION, AGENT_VERSION};

pub const CONFIG_PATH: &str = "/api/v1/reports/config";
pub const MANIFEST_PATH: &str = "/api/v1/manifest/config";

/// The most the report body may be: the server accepts 1 MiB on the wire; this leaves room.
pub const MAX_BODY_BYTES: usize = 1_000_000;

/// How long to wait before building again after a report could not be built at all.
const HOLD: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Startup,
    Scheduled,
    Requested,
    NewManifest,
}

impl Reason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Scheduled => "scheduled",
            Self::Requested => "requested",
            Self::NewManifest => "newer_manifest",
        }
    }
}

/// The manifest last fetched, with the validator for the next conditional request.
struct Cached {
    manifest: Manifest,
    etag: Option<String>,
}

struct Pending {
    report_id: String,
    body: Value,
    manifest_version: u64,
    reason: Reason,
    built_at: Instant,
}

pub struct Reporter<'a, R: Rng> {
    host: &'a dyn Host,
    interval: Duration,
    backoff: Backoff<R>,
    rng: R,
    cache: Option<Cached>,
    pending: Option<Pending>,
    retry_at: Option<Instant>,
    last_done: Option<Instant>,
    jitter_permille: u32,
    hold_until: Option<Instant>,
    /// A report is wanted now, and why.
    wanted: Option<Reason>,
    /// A report built for a request was accepted ([`Reporter::take_answered`]).
    answered: bool,
    /// Once requested, nothing new starts: no collection call, no send ([`Reporter::stopping_on`]).
    stop: Option<&'a Shutdown>,
    new_id: fn() -> std::io::Result<String>,
}

impl<'a, R: Rng> Reporter<'a, R> {
    pub fn new(host: &'a dyn Host, interval: Duration, backoff: Backoff<R>, rng: R) -> Self {
        Self {
            host,
            interval,
            backoff,
            rng,
            cache: None,
            pending: None,
            retry_at: None,
            last_done: None,
            jitter_permille: 0,
            hold_until: None,
            wanted: None,
            answered: false,
            stop: None,
            new_id: new_report_id,
        }
    }

    /// Stops starting work once `stop` is requested (Rust practice review of #114): the collection
    /// starts no command or filesystem call, a report collected meanwhile is dropped rather than sent,
    /// and nothing is fetched or sent after that. So SIGTERM during a tick ends it after the one
    /// request or call in flight, well inside systemd's 90 s stop timeout.
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

    /// Whether a report built for a request has been accepted since the last call, so the request it
    /// answered is over ([`super::requests::ReportRequests::answered`]).
    pub fn take_answered(&mut self) -> bool {
        std::mem::take(&mut self.answered)
    }

    #[cfg(test)]
    pub fn pending_report_id(&self) -> Option<&str> {
        self.pending.as_ref().map(|p| p.report_id.as_str())
    }

    /// Does whatever is due at `now` and returns when to call again.
    pub fn tick(&mut self, now: Instant, transport: &dyn Transport) -> Instant {
        // A request waits out a hold (after a failed manifest fetch) rather than retrying every poll.
        let held = self.hold_until.is_some_and(|hold| now < hold);
        if self.wanted.is_some() && !held {
            let reason = self.wanted.take().unwrap_or(Reason::Requested);
            self.build(reason, now, transport);
        } else if now >= self.build_due_at(now) {
            let reason = match &self.pending {
                Some(pending) => pending.reason,
                None if self.last_done.is_none() => Reason::Startup,
                None => Reason::Scheduled,
            };
            self.build(reason, now, transport);
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

    /// Fetches the manifest conditionally. The cached copy stands in for a failed fetch.
    fn manifest(&mut self, transport: &dyn Transport) -> Result<u64, ApiError> {
        let etag = self.cache.as_ref().and_then(|c| c.etag.clone());
        let fetched = match transport.get_conditional(MANIFEST_PATH, etag.as_deref()) {
            Ok(Conditional::NotModified) if self.cache.is_some() => Ok(()),
            Ok(Conditional::NotModified) => Err(ApiError::InvalidResponse(
                "304 for a manifest this agent does not have".into(),
            )),
            Ok(Conditional::Modified { body, etag }) => match manifest::parse(&body) {
                Ok(parsed) => {
                    for note in &parsed.notes {
                        tracing::warn!("manifest: {note}");
                    }
                    self.cache = Some(Cached {
                        manifest: parsed,
                        etag,
                    });
                    Ok(())
                }
                Err(e) => Err(ApiError::InvalidResponse(e)),
            },
            Err(e) => Err(e),
        };
        match (fetched, &self.cache) {
            (Ok(()), Some(cache)) => Ok(cache.manifest.version),
            (Err(e), Some(cache)) => {
                tracing::warn!(
                    manifest_version = cache.manifest.version,
                    "cannot fetch the config manifest ({e:?}); using the copy this agent has"
                );
                Ok(cache.manifest.version)
            }
            (Err(e), None) => Err(e),
            (Ok(()), None) => Err(ApiError::InvalidResponse("no manifest".into())),
        }
    }

    /// Builds a report with a new id, replacing any report still waiting.
    fn build(&mut self, reason: Reason, now: Instant, transport: &dyn Transport) {
        if self.stopping() {
            return;
        }
        if let Err(e) = self.manifest(transport) {
            let wait = self.backoff.on_failure(&e);
            tracing::warn!(
                retry_in_seconds = wait.as_secs(),
                "cannot fetch the config manifest ({e:?}); the config report waits"
            );
            self.hold_until = Some(now + wait);
            // A request is not forgotten because the manifest was unreachable.
            if reason == Reason::Requested || reason == Reason::NewManifest {
                self.wanted = Some(reason);
            }
            return;
        }
        let Some(cache) = self.cache.as_ref() else {
            return;
        };
        let report_id = match (self.new_id)() {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(
                    "cannot generate a report id ({e}); the config report is postponed"
                );
                self.hold_until = Some(now + HOLD);
                return;
            }
        };
        let version = cache.manifest.version;
        let collected_at = rfc3339(SystemTime::now());
        let mut collected = match self.stop {
            Some(stop) => facts::collect_until(self.host, &cache.manifest, stop),
            None => facts::collect(self.host, &cache.manifest),
        };
        if self.stopping() {
            // Collected while stopping: some facts may say only "the agent is stopping". Dropped,
            // not sent; the next start sends a startup report.
            tracing::info!(
                reason = reason.as_str(),
                "the agent is stopping; the config report just collected is not sent"
            );
            return;
        }
        let (body, shrunk) = build_body(&report_id, &collected_at, version, &mut collected);
        self.hold_until = None;
        // A new report is not held back by the failed attempts of the one it replaces.
        self.retry_at = None;
        let span = tracing::info_span!("config_report", report_id = report_id.as_str());
        let _entered = span.enter();
        let count = |s: State| collected.values().filter(|f| f.state() == s).count();
        tracing::info!(
            reason = reason.as_str(),
            manifest_version = version,
            facts = collected.len(),
            unreadable = count(State::Unreadable),
            unsupported = count(State::Unsupported),
            shrunk,
            replaced = self.pending.as_ref().map_or("", |p| p.report_id.as_str()),
            "collected the configuration facts"
        );
        self.pending = Some(Pending {
            report_id,
            body,
            manifest_version: version,
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
        let span = tracing::info_span!("config_report", report_id = pending.report_id.as_str());
        let _entered = span.enter();
        let reason = pending.reason.as_str();
        let requested = pending.reason == Reason::Requested;
        let used = pending.manifest_version;
        let attempt = self.backoff.failures() + 1;
        match transport.post(CONFIG_PATH, &pending.body) {
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
                    "config report sent"
                );
                let server_version = response
                    .body
                    .get("manifest_version")
                    .and_then(Value::as_u64);
                self.answered |= requested;
                self.finished(now);
                if let Some(server) = server_version
                    && server > used
                    && !self.stopping()
                {
                    self.follow_manifest(server, used, transport);
                }
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
                    "the server rejected the config report; it will not be retried, and the next report follows the normal schedule"
                );
                self.finished(now);
            }
            Err(error) => {
                self.retry_at = Some(now + self.backoff.on_failure(&error));
            }
        }
    }

    /// The server's manifest is newer than the one the accepted report used: fetch it, and rebuild only
    /// if what came back is newer than `used` (so a server ahead of its own endpoint cannot loop us).
    fn follow_manifest(&mut self, server: u64, used: u64, transport: &dyn Transport) {
        match self.manifest(transport) {
            Ok(fetched) if fetched > used => {
                tracing::info!(
                    server_manifest_version = server,
                    manifest_version = fetched,
                    "the server has a newer config manifest; reporting against it"
                );
                self.wanted = Some(Reason::NewManifest);
            }
            Ok(fetched) => tracing::warn!(
                server_manifest_version = server,
                manifest_version = fetched,
                "the server names a newer manifest than its manifest endpoint serves; not rebuilding"
            ),
            Err(_) => {}
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

/// The `config.request` body, with the largest facts turned `unreadable` until it is within
/// [`MAX_BODY_BYTES`]. Returns the body and how many facts were turned.
fn build_body(
    report_id: &str,
    collected_at: &str,
    manifest_version: u64,
    collected: &mut BTreeMap<String, Fact>,
) -> (Value, usize) {
    let mut shrunk = 0;
    let size = |facts: &BTreeMap<String, Fact>| -> usize {
        facts
            .iter()
            .map(|(k, f)| k.len() + serde_json::to_vec(f).map_or(0, |v| v.len()) + 4)
            .sum::<usize>()
    };
    let mut total = size(collected) + 512;
    if total > MAX_BODY_BYTES {
        let mut by_size: Vec<(usize, String)> = collected
            .iter()
            .filter(|(_, f)| f.state() == State::Ok)
            .map(|(k, f)| (serde_json::to_vec(f).map_or(0, |v| v.len()), k.clone()))
            .collect();
        by_size.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        for (bytes, key) in by_size {
            if total <= MAX_BODY_BYTES {
                break;
            }
            let replacement = Fact::unreadable(
                "the value is too large to report; the agent's report would exceed the server's size limit",
            );
            let small = serde_json::to_vec(&replacement).map_or(0, |v| v.len());
            collected.insert(key, replacement);
            total = total.saturating_sub(bytes.saturating_sub(small));
            shrunk += 1;
        }
    }
    let body = json!({
        "schema_version": AGENT_SCHEMA_VERSION,
        "agent_version": AGENT_VERSION,
        "report_id": report_id,
        "collected_at": collected_at,
        "manifest_version": manifest_version,
        "facts": collected,
    });
    (body, shrunk)
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

#[cfg(test)]
mod tests;
