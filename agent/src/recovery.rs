//! Recovery mode (#180, ADR 0030): what keeps an agent reachable when it keeps failing on a version it
//! has already confirmed, so nothing can be rolled back.
//!
//! systemd decides that the agent is crash-looping (`StartLimitBurst=` in `fleet-agent.service`), and
//! its `OnFailure=` starts the rollback unit and then `fleet-agent-recovery.service`, which runs this
//! binary as `fleet-agent run --recovery` ([`crate::report::run_recovery`]). Nothing else starts it: no
//! directive, no field of any response, and no file the server can write. In recovery mode the agent
//! only authenticates, sends heartbeats that carry [`Status`] (the reason and since when), posts update
//! results, and installs a signed update offered through the usual path (ADR 0018). It runs no
//! collector, sends no report, and polls for no task.
//!
//! `fleet-agent.service` sets `RestartMode=direct`, so `OnFailure=` runs only once it has given up;
//! without it, systemd 254 and later run it after every failed start. As a fallback recovery mode still
//! checks the service for [`SETTLE`] ([`look`]): it goes on only if the service stays `failed` and
//! enabled, exits if it runs or a person disabled, masked, or reset it, and fails (so systemd retries it
//! later) if `systemctl` cannot say. It never starts a service a person disabled, masked, or reset. A
//! plain `systemctl stop` of the failed service is not seen (it stays `failed`).
//!
//! It leaves recovery mode when `fleet-agent.service` runs again, or a person stops or disables it,
//! which it checks every [`WATCH_EVERY`]: after an update (the supervisor restarts the service), when an operator starts it,
//! or when recovery mode itself tries normal mode again, [`RETRY_AFTER`] after it started.
//!
//! This module keeps two records in the state directory:
//!
//! - [`LAST_FAILURE`], written by an agent that stops with an error (a loop that panicked, say), so
//!   recovery mode can say why;
//! - [`RECORD`], the recovery episode: when it began and the latest reason. It survives the hourly tries
//!   of normal mode, and normal mode removes both records once it has run for [`HEALTHY_AFTER`].

use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::report::rfc3339;
use crate::update::supervise::unix;

/// The recovery episode ([`Episode`]).
pub const RECORD: &str = "recovery.json";

/// Why the agent last stopped with an error ([`LastFailure`]).
pub const LAST_FAILURE: &str = "last-failure.json";

/// How long recovery mode runs before it tries normal mode again.
pub const RETRY_AFTER: Duration = Duration::from_secs(60 * 60);

/// How long normal mode must run before the episode is over. Longer than systemd's start-limit window
/// (300 s), so an agent that keeps failing never gets this far.
pub const HEALTHY_AFTER: Duration = Duration::from_secs(10 * 60);

/// How often recovery mode checks whether `fleet-agent.service` runs again.
pub const WATCH_EVERY: Duration = Duration::from_secs(3);

/// How long recovery mode watches the service before it decides. With `RestartMode=direct` in
/// `fleet-agent.service` (systemd 254 and later) `OnFailure=` starts this unit only once the service has
/// given up, so this is a fallback: longer than the service's `RestartSec=10s`, for a systemd that starts
/// it while a restart is still pending (and reports the service `failed` meanwhile).
pub const SETTLE: Duration = Duration::from_secs(20);

/// What `systemctl is-active fleet-agent.service` says, as recovery mode reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// `active`, `activating`, `reloading`, `refreshing`: it runs, or systemd is starting it.
    Runs,
    /// `failed`: what a crash loop that hit the start limit (or an exit 78) leaves.
    Failed,
    /// `inactive`: what a person's `systemctl stop` (or `reset-failed`) leaves. Recovery mode stays out.
    Stopped,
    /// Anything else, including an error or a timeout of `systemctl` itself.
    Unreadable,
}

pub fn service_of(is_active: &str) -> Service {
    match is_active.trim() {
        "active" | "activating" | "reloading" | "refreshing" => Service::Runs,
        "failed" => Service::Failed,
        "inactive" => Service::Stopped,
        _ => Service::Unreadable,
    }
}

/// Whether `systemctl is-enabled fleet-agent.service` says a person disabled or masked it (`Some(true)`),
/// that it is enabled (`Some(false)`), or cannot be read (`None`).
pub fn disabled_by_operator(is_enabled: &str) -> Option<bool> {
    match is_enabled.trim() {
        "disabled" | "masked" | "masked-runtime" => Some(true),
        "enabled" | "enabled-runtime" | "static" | "indirect" | "generated" | "alias"
        | "linked" | "linked-runtime" | "transient" => Some(false),
        _ => None,
    }
}

/// One look at the service, as recovery mode decides what to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Look {
    /// It runs or is starting: recovery mode is not needed (or must end).
    Runs,
    /// A person stopped or disabled it: recovery mode stays out, and never starts it.
    OperatorStopped,
    /// Failed and still enabled: what recovery mode is for.
    Failed,
    /// Cannot tell (`systemctl` failed, timed out, or said something else): look again.
    Unreadable,
}

pub fn look(is_active: &str, is_enabled: &str) -> Look {
    match (service_of(is_active), disabled_by_operator(is_enabled)) {
        (Service::Runs, _) => Look::Runs,
        (Service::Stopped, _) | (_, Some(true)) => Look::OperatorStopped,
        (Service::Failed, Some(false)) => Look::Failed,
        _ => Look::Unreadable,
    }
}

/// A recorded failure older than this did not cause this crash loop.
const FAILURE_FRESH_FOR: Duration = Duration::from_secs(15 * 60);

/// Longest reason a heartbeat carries (`heartbeat.request` `recovery.reason`).
pub const MAX_REASON_CHARS: usize = 256;

/// The largest record this module reads.
const MAX_RECORD_BYTES: u64 = 4096;

/// What a heartbeat in recovery mode carries (`heartbeat.request` `recovery`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    /// When this episode began (the agent's clock).
    pub entered_at: String,
    pub reason: String,
    /// When recovery mode will try normal mode again (the agent's clock).
    pub retry_at: String,
}

/// [`LAST_FAILURE`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastFailure {
    pub at: String,
    pub at_unix: u64,
    pub reason: String,
}

/// [`RECORD`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Episode {
    pub entered_at: String,
    pub entered_unix: u64,
    pub reason: String,
    /// How many times recovery mode has started in this episode.
    pub starts: u32,
}

fn read<T: for<'de> Deserialize<'de>>(state_dir: &Path, name: &str) -> Option<T> {
    let bytes = crate::state::read_record(state_dir, name, MAX_RECORD_BYTES).ok()??;
    serde_json::from_slice(&bytes).ok()
}

fn write<T: Serialize>(state_dir: &Path, name: &str, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    crate::state::write_record(state_dir, name, &bytes)
}

/// `text` as a reason: one line of plain text, at most [`MAX_REASON_CHARS`] characters, never empty. No
/// C0 or C1 control (replaced by a space, as `logging::sanitize` does), no line or paragraph separator
/// (a space too), and no bidirectional formatting character (removed), as `heartbeat.request` requires.
pub fn reason_text(text: &str) -> String {
    let bidi = |c: char| {
        matches!(
            c,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
    };
    let plain: String = text
        .chars()
        .filter(|c| !bidi(*c))
        .map(|c| {
            if matches!(c, '\u{2028}' | '\u{2029}') {
                ' '
            } else {
                c
            }
        })
        .collect();
    let line = crate::logging::sanitize(&plain, MAX_REASON_CHARS);
    match line.trim() {
        "" => "no reason was recorded".to_owned(),
        trimmed => trimmed.to_owned(),
    }
}

/// Records why the agent is stopping with an error, for recovery mode to report.
pub fn record_failure(state_dir: &Path, why: &str, now: SystemTime) {
    let failure = LastFailure {
        at: rfc3339(now),
        at_unix: unix(now),
        reason: reason_text(why),
    };
    if let Err(e) = write(state_dir, LAST_FAILURE, &failure) {
        tracing::warn!("cannot record why the agent stopped: {e}");
    }
}

/// Normal mode has run for [`HEALTHY_AFTER`]: the episode, if any, is over. `true` if there was one.
pub fn clear(state_dir: &Path) -> bool {
    let had = state_dir.join(RECORD).exists();
    for name in [RECORD, LAST_FAILURE] {
        match fs::remove_file(state_dir.join(name)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("cannot remove {name} from the state directory: {e}"),
        }
    }
    had
}

/// What systemd says about the failure that started this unit: `OnFailure=` sets these for the unit it
/// starts (systemd 251 and later). `None` without them (an older systemd, or a restart of the recovery
/// unit itself).
pub fn monitor_reason(env: impl Fn(&str) -> Option<String>) -> Option<String> {
    let result = env("MONITOR_SERVICE_RESULT").filter(|v| !v.is_empty())?;
    let code = env("MONITOR_EXIT_CODE").filter(|v| !v.is_empty());
    let status = env("MONITOR_EXIT_STATUS").filter(|v| !v.is_empty());
    Some(match (code, status) {
        (Some(code), Some(status)) => format!("{result}, last exit {code} {status}"),
        _ => result,
    })
}

/// Recovery mode is starting at `now`: the episode as it is now, and its record written. The reason is
/// the agent's own record of why it stopped when there is a recent one, with what systemd said
/// (`monitor`, [`monitor_reason`]); otherwise what systemd said; otherwise the reason already recorded
/// for this episode.
pub fn begin(state_dir: &Path, now: SystemTime, monitor: Option<String>) -> Episode {
    let now_unix = unix(now);
    let failure = read::<LastFailure>(state_dir, LAST_FAILURE)
        .filter(|f| f.at_unix <= now_unix && now_unix - f.at_unix <= FAILURE_FRESH_FOR.as_secs());
    let earlier = read::<Episode>(state_dir, RECORD);
    let reason = match (failure, monitor) {
        (Some(failure), Some(monitor)) => format!("{} (systemd: {monitor})", failure.reason),
        (Some(failure), None) => failure.reason,
        (None, Some(monitor)) => {
            format!(
                "fleet-agent.service kept failing and systemd stopped restarting it ({monitor})"
            )
        }
        (None, None) => earlier.as_ref().map_or_else(
            || "fleet-agent.service kept failing; no reason was recorded".to_owned(),
            |e| e.reason.clone(),
        ),
    };
    let episode = match earlier {
        Some(earlier) => Episode {
            reason: reason_text(&reason),
            starts: earlier.starts.saturating_add(1),
            ..earlier
        },
        None => Episode {
            entered_at: rfc3339(now),
            entered_unix: now_unix,
            reason: reason_text(&reason),
            starts: 1,
        },
    };
    if let Err(e) = write(state_dir, RECORD, &episode) {
        tracing::warn!("cannot record the recovery episode: {e}");
    }
    episode
}

/// The first panic of this process, as one line: where and what.
static FIRST_PANIC: OnceLock<Mutex<Option<String>>> = OnceLock::new();

/// Keeps the first panic's message for [`panic_summary`], then panics as before (the default hook
/// prints it to the journal).
pub fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let slot = FIRST_PANIC.get_or_init(|| Mutex::new(None));
        let mut first = slot.lock().unwrap_or_else(|e| e.into_inner());
        if first.is_none() {
            *first = Some(describe_panic(
                std::thread::current().name(),
                info.location().map(|l| (l.file(), l.line())),
                info.payload(),
            ));
        }
        drop(first);
        previous(info);
    }));
}

fn describe_panic(
    thread: Option<&str>,
    at: Option<(&str, u32)>,
    payload: &(dyn std::any::Any + Send),
) -> String {
    let message = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "(no message)".to_owned());
    let thread = thread.unwrap_or("an unnamed thread");
    match at {
        Some((file, line)) => format!("panicked in {thread} at {file}:{line}: {message}"),
        None => format!("panicked in {thread}: {message}"),
    }
}

/// The first panic of this process ([`install_panic_hook`]), if there was one.
pub fn panic_summary() -> Option<String> {
    FIRST_PANIC
        .get()
        .and_then(|slot| slot.lock().unwrap_or_else(|e| e.into_inner()).clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use std::time::UNIX_EPOCH;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn recovery_mode_goes_on_only_for_a_failed_enabled_service_and_never_on_a_guess() {
        // Only a clear answer decides anything; an error from systemctl is not "stopped".
        for (active, enabled, expected) in [
            ("active", "enabled", Look::Runs),
            ("activating", "disabled", Look::Runs),
            ("reloading", "", Look::Runs),
            ("failed", "enabled", Look::Failed),
            ("failed", "static", Look::Failed),
            ("inactive", "enabled", Look::OperatorStopped),
            ("failed", "disabled", Look::OperatorStopped),
            ("failed", "masked", Look::OperatorStopped),
            (
                "failed",
                "Failed to connect to bus: No such file or directory",
                Look::Unreadable,
            ),
            (
                "Failed to connect to bus: No such file or directory",
                "enabled",
                Look::Unreadable,
            ),
            (
                "systemctl is-active fleet-agent.service did not finish within 60 seconds and was stopped",
                "enabled",
                Look::Unreadable,
            ),
            ("deactivating", "enabled", Look::Unreadable),
            ("", "", Look::Unreadable),
        ] {
            assert_eq!(look(active, enabled), expected, "{active:?} {enabled:?}");
        }
    }

    #[test]
    fn a_reason_is_one_short_line_of_plain_text() {
        assert_eq!(reason_text("  \n "), "no reason was recorded");
        assert_eq!(reason_text("line one\nline two\t!"), "line one line two !");
        assert_eq!(
            reason_text("abc\u{202e}fed\u{2066}x\u{2069}"),
            "abcfedx",
            "bidirectional controls would make the dashboard show something else"
        );
        assert_eq!(
            reason_text("a\u{85}b\u{2028}c\u{200f}d\u{61c}e\u{9f}"),
            "a b cde",
            "C1 controls and separators become spaces; marks are removed"
        );
        let long = "x".repeat(1000);
        assert_eq!(reason_text(&long).chars().count(), MAX_REASON_CHARS);
    }

    #[test]
    fn systemds_account_of_the_failure_is_read_from_its_environment() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |key: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        assert_eq!(monitor_reason(env(&[])), None);
        assert_eq!(monitor_reason(env(&[("MONITOR_SERVICE_RESULT", "")])), None);
        assert_eq!(
            monitor_reason(env(&[
                ("MONITOR_SERVICE_RESULT", "start-limit-hit"),
                ("MONITOR_EXIT_CODE", "exited"),
                ("MONITOR_EXIT_STATUS", "1"),
            ])),
            Some("start-limit-hit, last exit exited 1".into())
        );
        assert_eq!(
            monitor_reason(env(&[("MONITOR_SERVICE_RESULT", "exit-code")])),
            Some("exit-code".into())
        );
    }

    #[test]
    fn an_episode_says_why_and_keeps_when_it_began_until_normal_mode_has_run() {
        let dir = TempDir::new();
        let state = dir.root();
        // Nothing recorded and nothing from systemd.
        let first = begin(state, at(1_000), None);
        assert_eq!(first.entered_unix, 1_000);
        assert_eq!(first.starts, 1);
        assert_eq!(
            first.reason,
            "fleet-agent.service kept failing; no reason was recorded"
        );

        // The agent recorded why it stopped, and systemd says how it ended: both are reported, and the
        // episode keeps its start.
        record_failure(state, "the inventory loop failed: panicked", at(1_500));
        let second = begin(
            state,
            at(1_600),
            Some("start-limit-hit, last exit exited 1".into()),
        );
        assert_eq!(second.entered_unix, 1_000);
        assert_eq!(second.entered_at, first.entered_at);
        assert_eq!(second.starts, 2);
        assert_eq!(
            second.reason,
            "the inventory loop failed: panicked (systemd: start-limit-hit, last exit exited 1)"
        );

        // A restart of recovery mode itself, long after: the old failure is stale, systemd says
        // nothing, so the reason stays.
        let third = begin(state, at(1_600 + 3_600), None);
        assert_eq!(third.reason, second.reason);
        assert_eq!(third.starts, 3);

        // Only systemd's account.
        assert!(clear(state));
        assert!(!state.join(RECORD).exists() && !state.join(LAST_FAILURE).exists());
        assert!(!clear(state), "nothing to clear");
        let fresh = begin(state, at(9_000), Some("exit-code".into()));
        assert_eq!(fresh.entered_unix, 9_000);
        assert_eq!(
            fresh.reason,
            "fleet-agent.service kept failing and systemd stopped restarting it (exit-code)"
        );
        // A failure recorded "later" than now (a clock step back) is not taken for this one.
        record_failure(state, "from the future", at(20_000));
        assert!(!begin(state, at(9_100), None).reason.contains("future"));
    }

    #[test]
    fn unreadable_records_are_ignored() {
        let dir = TempDir::new();
        dir.write(RECORD, "not json");
        dir.write(LAST_FAILURE, "{}");
        let episode = begin(dir.root(), at(5), None);
        assert_eq!(episode.starts, 1);
        assert_eq!(episode.entered_unix, 5);
    }

    #[test]
    fn the_records_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new();
        record_failure(dir.root(), "x", at(1));
        begin(dir.root(), at(2), None);
        for name in [RECORD, LAST_FAILURE] {
            let mode = fs::metadata(dir.root().join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
    }

    #[test]
    fn a_panic_is_described_in_one_line() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("boom");
        assert_eq!(
            describe_panic(
                Some("fleet-agent-inventory"),
                Some(("src/x.rs", 7)),
                &*payload
            ),
            "panicked in fleet-agent-inventory at src/x.rs:7: boom"
        );
        let payload: Box<dyn std::any::Any + Send> = Box::new(String::from("owned"));
        assert_eq!(
            describe_panic(None, None, &*payload),
            "panicked in an unnamed thread: owned"
        );
        let payload: Box<dyn std::any::Any + Send> = Box::new(42_u8);
        assert!(describe_panic(None, None, &*payload).ends_with("(no message)"));
    }
}
