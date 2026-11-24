//! The agent process and its systemd service, as heartbeats report them (#251).
//!
//! A slowly leaking agent is killed at `MemoryMax=` and restarted by systemd 10 s later. If the kills
//! come minutes apart it never reaches the start limit, so it never enters recovery mode, and every
//! process heartbeats normally. The heartbeat's `process` object lets the server see it:
//!
//! - `started_at`: when this process started (its own clock), fixed for its life, so a new value means
//!   a new process;
//! - `restarts`: systemd's `NRestarts` for `fleet-agent.service`, read with one `systemctl show` when the
//!   process starts ([`restarts`]). It only changes when systemd starts a new process, so one read per
//!   process is enough; a read that fails is tried again at the next heartbeat;
//! - `last_stop`: how the process before this one stopped. systemd resets `Result`, `ExecMainCode`, and
//!   `ExecMainStatus` when it starts the service again, so the running agent cannot read them for the run
//!   before its own. systemd gives them to `ExecStopPost=` instead (`$SERVICE_RESULT`, `$EXIT_CODE`,
//!   `$EXIT_STATUS`), and the unit runs `fleet-agent note-stop` there, which writes [`LAST_STOP`] in the
//!   state directory ([`note_stop`]). The next process reads it once, at its start, and removes it
//!   ([`Start::read`]), so a stop that wrote no record (a power loss, a hard reset, a kernel panic, or a write
//!   that failed) is reported as unknown, never as the stop before it (review of #307, S3).
//!
//! `note-stop` runs under the service's own sandbox, as root like the service, and only writes that
//! record: no privilege is added, and the unit's `systemd-analyze security` exposure is unchanged. Every
//! value is checked and capped where it is read: a record of at most [`MAX_RECORD_BYTES`], a result of at
//! most 32 lowercase letters and hyphens, an exit code systemd uses, and a status from 0 to 255.

use std::path::Path;
use std::process::ExitCode;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::report::{parse_rfc3339, rfc3339};

/// The record `note-stop` writes in the state directory ([`LastStop`]).
pub const LAST_STOP: &str = "last-stop.json";

/// The subcommand the unit's `ExecStopPost=` runs.
pub const NOTE_STOP: &str = "note-stop";

/// Most of [`LAST_STOP`] that is read: the record is about 120 bytes.
const MAX_RECORD_BYTES: u64 = 1024;

/// Longest `result` kept (systemd's longest today, `start-limit-hit`, has 15 characters).
const MAX_RESULT: usize = 32;

/// How the process before this one stopped (`process.last_stop`), as systemd told `ExecStopPost=`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastStop {
    /// systemd's `$SERVICE_RESULT`: `success`, `exit-code`, `signal`, `oom-kill`, ...
    pub result: String,
    /// `$EXIT_CODE`: `exited`, `killed`, or `dumped`; `None` when systemd did not say.
    pub exit_code: Option<String>,
    /// `$EXIT_STATUS`: the exit status, or the signal's number for `killed` and `dumped`.
    pub exit_status: Option<u8>,
    /// When `note-stop` wrote the record, by the agent's clock.
    pub stopped_at: String,
}

/// `process` in `heartbeat.request` (docs/api/schemas/v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub started_at: String,
    pub restarts: Option<u32>,
    pub last_stop: Option<LastStop>,
}

/// What the heartbeat knows of this process from its start: when it started and the record of the stop
/// before it, each read once. `restarts` is read by the heartbeat ([`restarts`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Start {
    pub started_at: String,
    pub last_stop: Option<LastStop>,
}

impl Start {
    /// The process started at `started` (wall clock); the stop record is read from `state_dir` now and removed, so
    /// it describes only the stop just before this process. A record that cannot be removed is reported all the same,
    /// with a warning: the next process could then report it again.
    pub fn read(state_dir: &Path, started: SystemTime) -> Self {
        let last_stop = read_last_stop(state_dir);
        match std::fs::remove_file(state_dir.join(LAST_STOP)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(
                "cannot remove {LAST_STOP} after reading it ({e}); if the agent next stops without systemd running its stop hook, that stop may be reported as this one"
            ),
        }
        Self {
            started_at: rfc3339(started),
            last_stop,
        }
    }
}

/// systemd's `NRestarts` for `fleet-agent.service`: one `systemctl show`, which works inside the sandbox
/// (`AF_UNIX`), bounded by the runner's time limit. A systemd too old to have the property (before 235)
/// prints nothing, which is an error like any other answer that is not a count.
pub fn restarts(systemd: &dyn crate::install::Systemd) -> Result<u32, String> {
    let output = systemd
        .systemctl(&[
            "show",
            "--property=NRestarts",
            "--value",
            crate::install::UNIT_NAME,
        ])
        .map_err(|e| format!("systemctl show failed: {e}"))?;
    let text = output.trim();
    text.parse::<u32>().map_err(|_| {
        format!(
            "systemctl show printed {} for NRestarts, not a count",
            crate::cli::shown(text)
        )
    })
}

/// [`LAST_STOP`] from `state_dir`, if there is one and every value in it is one systemd could have given.
/// Anything else (unreadable, too large, not JSON, a value out of range) is `None`, with a warning: the
/// heartbeat then says there is no record.
pub fn read_last_stop(state_dir: &Path) -> Option<LastStop> {
    let bytes = match crate::state::read_record(state_dir, LAST_STOP, MAX_RECORD_BYTES) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return None,
        Err(e) => {
            tracing::warn!(
                "cannot read {LAST_STOP} ({e}); heartbeats say how the agent last stopped is not known"
            );
            return None;
        }
    };
    let stop = serde_json::from_slice::<LastStop>(&bytes)
        .ok()
        .filter(valid);
    if stop.is_none() {
        tracing::warn!(
            "{LAST_STOP} is not a record this agent wrote; heartbeats say how the agent last stopped is not known"
        );
    }
    stop
}

fn valid(stop: &LastStop) -> bool {
    valid_result(&stop.result)
        && match stop.exit_code.as_deref() {
            None => stop.exit_status.is_none(),
            Some("exited") => stop.exit_status.is_some(),
            Some("killed" | "dumped") => stop.exit_status.is_none_or(|s| (1..=64).contains(&s)),
            Some(_) => false,
        }
        && parse_rfc3339(&stop.stopped_at).is_some()
        && stop.stopped_at.len() <= 35
}

/// A systemd result word: 1 to [`MAX_RESULT`] lowercase ASCII letters and hyphens, starting with a letter.
fn valid_result(result: &str) -> bool {
    !result.is_empty()
        && result.len() <= MAX_RESULT
        && result.starts_with(|c: char| c.is_ascii_lowercase())
        && result.chars().all(|c| c.is_ascii_lowercase() || c == '-')
}

/// The record for what systemd put in `ExecStopPost=`'s environment, or `None` when `SERVICE_RESULT` is
/// missing or not a result word (not run by systemd, or a systemd before 232). An `EXIT_CODE` systemd does
/// not use, or an `EXIT_STATUS` that does not fit it, leaves both out.
pub fn last_stop_from(env: impl Fn(&str) -> Option<String>, now: SystemTime) -> Option<LastStop> {
    let result = env("SERVICE_RESULT").filter(|r| valid_result(r))?;
    let status = env("EXIT_STATUS");
    let code = env("EXIT_CODE");
    let (exit_code, exit_status) = match code.as_deref() {
        Some("exited") => match status.as_deref().and_then(|s| s.parse::<u8>().ok()) {
            Some(status) => (Some("exited"), Some(status)),
            None => (None, None),
        },
        Some(code @ ("killed" | "dumped")) => {
            (Some(code), status.as_deref().and_then(signal_number))
        }
        _ => (None, None),
    };
    Some(LastStop {
        result,
        exit_code: exit_code.map(str::to_owned),
        exit_status,
        stopped_at: rfc3339(now),
    })
}

/// The number of a signal as systemd names it in `$EXIT_STATUS` (`KILL`, `SEGV`, `RTMIN+3`), or a number
/// it printed as is. `None` for a name this agent does not know.
pub fn signal_number(name: &str) -> Option<u8> {
    const NAMES: [&str; 31] = [
        "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2",
        "PIPE", "ALRM", "TERM", "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG",
        "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH", "IO", "PWR", "SYS",
    ];
    let name = name.trim();
    let name = name.strip_prefix("SIG").unwrap_or(name);
    if let Some(at) = NAMES.iter().position(|n| *n == name) {
        return u8::try_from(at + 1).ok();
    }
    // Linux's real-time signals run from SIGRTMIN (34, as glibc and musl report it) to 64.
    let realtime = |base: u8, offset: &str, sign: i16| -> Option<u8> {
        let offset: i16 = if offset.is_empty() {
            0
        } else {
            offset.parse().ok()?
        };
        u8::try_from(i16::from(base) + sign * offset)
            .ok()
            .filter(|n| (34..=64).contains(n))
    };
    if let Some(rest) = name.strip_prefix("RTMIN") {
        return realtime(34, rest.strip_prefix('+').unwrap_or(rest), 1);
    }
    if let Some(rest) = name.strip_prefix("RTMAX") {
        return realtime(64, rest.strip_prefix('-').unwrap_or(rest), -1);
    }
    name.parse::<u8>().ok().filter(|n| (1..=64).contains(n))
}

/// `fleet-agent note-stop [--config PATH]`, run by the unit's `ExecStopPost=` after every stop of the
/// service: writes [`LAST_STOP`] in the config's state directory (the default one if the config cannot
/// be loaded) from what systemd put in the environment. It never fails the stop: the unit prefixes it with
/// `-`, and it exits 0 whatever happens, saying on stderr (the journal) what went wrong. Nothing but the
/// record is written, and nothing is sent.
pub fn main(args: Vec<std::ffi::OsString>) -> ExitCode {
    let config = match parse_args(args) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("fleet-agent {NOTE_STOP}: {message}");
            return ExitCode::from(2);
        }
    };
    let state_dir = match crate::config::Config::load(&config) {
        Ok(config) => config.state_dir,
        Err(_) => std::path::PathBuf::from(crate::config::DEFAULT_STATE_DIR),
    };
    if let Err(why) = note_stop(&state_dir, |key| std::env::var(key).ok(), SystemTime::now()) {
        eprintln!("fleet-agent {NOTE_STOP}: {why}");
    }
    ExitCode::SUCCESS
}

/// Writes the record for this environment in `state_dir` (atomically, mode 0600).
pub fn note_stop(
    state_dir: &Path,
    env: impl Fn(&str) -> Option<String>,
    now: SystemTime,
) -> Result<(), String> {
    let stop = last_stop_from(env, now)
        .ok_or_else(|| "no SERVICE_RESULT from systemd; nothing recorded".to_owned())?;
    let bytes = serde_json::to_vec(&stop).map_err(|e| e.to_string())?;
    crate::state::write_record(state_dir, LAST_STOP, &bytes)
        .map_err(|e| format!("cannot write {LAST_STOP} in {}: {e}", state_dir.display()))
}

/// The config path from `note-stop`'s arguments (the first is the subcommand): `--config PATH` or `-c
/// PATH`, at most once, and nothing else.
fn parse_args(args: Vec<std::ffi::OsString>) -> Result<std::path::PathBuf, String> {
    use lexopt::prelude::*;
    let mut parser = lexopt::Parser::from_args(args.into_iter().skip(1));
    let mut config = None;
    while let Some(arg) = parser.next().map_err(crate::cli::error_text)? {
        match arg {
            Short('c') | Long("config") => {
                let path = parser.value().map_err(crate::cli::error_text)?;
                if path.is_empty() {
                    return Err("--config needs a path".into());
                }
                if config.replace(std::path::PathBuf::from(path)).is_some() {
                    return Err("--config given more than once".into());
                }
            }
            other => {
                return Err(format!("unrecognised argument: {}", crate::cli::arg(other)));
            }
        }
    }
    Ok(config.unwrap_or_else(|| std::path::PathBuf::from(crate::config::DEFAULT_CONFIG_PATH)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use std::collections::HashMap;
    use std::time::{Duration, UNIX_EPOCH};

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |key| map.get(key).cloned()
    }

    fn at() -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(1_767_268_789_512)
    }

    #[test]
    fn a_kill_at_the_memory_limit_is_recorded_with_the_signal_number() {
        let stop = last_stop_from(
            env(&[
                ("SERVICE_RESULT", "oom-kill"),
                ("EXIT_CODE", "killed"),
                ("EXIT_STATUS", "KILL"),
            ]),
            at(),
        )
        .unwrap();
        assert_eq!(
            stop,
            LastStop {
                result: "oom-kill".into(),
                exit_code: Some("killed".into()),
                exit_status: Some(9),
                stopped_at: "2026-01-01T11:59:49.512Z".into(),
            }
        );
    }

    #[test]
    fn an_exit_keeps_its_status_and_a_missing_or_odd_code_keeps_neither() {
        let exited = |status: &str| {
            last_stop_from(
                env(&[
                    ("SERVICE_RESULT", "exit-code"),
                    ("EXIT_CODE", "exited"),
                    ("EXIT_STATUS", status),
                ]),
                at(),
            )
            .unwrap()
        };
        assert_eq!(exited("1").exit_status, Some(1));
        assert_eq!(exited("1").exit_code.as_deref(), Some("exited"));
        for odd in ["256", "-1", "KILL", ""] {
            let stop = exited(odd);
            assert_eq!((stop.exit_code, stop.exit_status), (None, None), "{odd}");
        }
        let never = last_stop_from(env(&[("SERVICE_RESULT", "resources")]), at()).unwrap();
        assert_eq!((never.exit_code, never.exit_status), (None, None));
        let odd = last_stop_from(
            env(&[
                ("SERVICE_RESULT", "signal"),
                ("EXIT_CODE", "crashed"),
                ("EXIT_STATUS", "9"),
            ]),
            at(),
        )
        .unwrap();
        assert_eq!((odd.exit_code, odd.exit_status), (None, None));
    }

    #[test]
    fn without_a_result_word_from_systemd_nothing_is_recorded() {
        for result in ["", "OOM-KILL", "oom kill", "-x", &"a".repeat(33), "kill\n"] {
            assert!(
                last_stop_from(env(&[("SERVICE_RESULT", result)]), at()).is_none(),
                "{result:?}"
            );
        }
        assert!(last_stop_from(env(&[]), at()).is_none());
        assert!(last_stop_from(env(&[("SERVICE_RESULT", &"a".repeat(32))]), at()).is_some());
    }

    #[test]
    fn signal_names_are_numbered_as_linux_numbers_them() {
        for (name, number) in [
            ("HUP", Some(1)),
            ("KILL", Some(9)),
            ("SIGKILL", Some(9)),
            ("SEGV", Some(11)),
            ("TERM", Some(15)),
            ("SYS", Some(31)),
            ("RTMIN", Some(34)),
            ("RTMIN+3", Some(37)),
            ("RTMAX", Some(64)),
            ("RTMAX-1", Some(63)),
            ("RTMIN+31", None),
            ("RTMAX-31", None),
            ("12", Some(12)),
            ("65", None),
            ("0", None),
            ("NOPE", None),
            ("", None),
        ] {
            assert_eq!(signal_number(name), number, "{name}");
        }
    }

    #[test]
    fn the_record_note_stop_writes_is_the_one_the_next_process_reads() {
        let dir = TempDir::new();
        assert_eq!(read_last_stop(dir.root()), None);
        note_stop(
            dir.root(),
            env(&[
                ("SERVICE_RESULT", "oom-kill"),
                ("EXIT_CODE", "killed"),
                ("EXIT_STATUS", "KILL"),
            ]),
            at(),
        )
        .unwrap();
        let mode = std::fs::metadata(dir.path(LAST_STOP)).unwrap();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o777,
            0o600
        );
        let stop = read_last_stop(dir.root()).unwrap();
        assert_eq!(stop.result, "oom-kill");
        assert_eq!(stop.exit_status, Some(9));
        let start = Start::read(dir.root(), at());
        assert_eq!(start.started_at, "2026-01-01T11:59:49.512Z");
        assert_eq!(start.last_stop, Some(stop));
        // Read once: the next process, after a stop that wrote nothing (a power loss), knows of no stop.
        assert!(!dir.path(LAST_STOP).exists());
        assert_eq!(Start::read(dir.root(), at()).last_stop, None);
        assert!(note_stop(dir.root(), env(&[]), at()).is_err());
        assert!(!dir.path(LAST_STOP).exists());
    }

    #[test]
    fn a_record_with_any_value_systemd_could_not_have_given_is_not_reported() {
        let dir = TempDir::new();
        let good = r#"{"result":"oom-kill","exit_code":"killed","exit_status":9,"stopped_at":"2026-01-01T11:59:49.512Z"}"#;
        dir.write(LAST_STOP, good);
        assert!(read_last_stop(dir.root()).is_some());
        for bad in [
            "not json",
            r#"{"result":"OOM","exit_code":"killed","exit_status":9,"stopped_at":"2026-01-01T11:59:49.512Z"}"#,
            r#"{"result":"oom-kill","exit_code":"crashed","exit_status":9,"stopped_at":"2026-01-01T11:59:49.512Z"}"#,
            r#"{"result":"oom-kill","exit_code":"killed","exit_status":200,"stopped_at":"2026-01-01T11:59:49.512Z"}"#,
            r#"{"result":"oom-kill","exit_code":"killed","exit_status":300,"stopped_at":"2026-01-01T11:59:49.512Z"}"#,
            r#"{"result":"oom-kill","exit_code":"exited","exit_status":null,"stopped_at":"2026-01-01T11:59:49.512Z"}"#,
            r#"{"result":"oom-kill","exit_code":null,"exit_status":1,"stopped_at":"2026-01-01T11:59:49.512Z"}"#,
            r#"{"result":"oom-kill","exit_code":"killed","exit_status":9,"stopped_at":"yesterday"}"#,
            r#"{"result":"oom-kill","exit_code":"killed","exit_status":9}"#,
        ] {
            dir.write(LAST_STOP, bad);
            assert_eq!(read_last_stop(dir.root()), None, "{bad}");
        }
        dir.write(LAST_STOP, &format!("{good}{}", " ".repeat(2000)));
        assert_eq!(read_last_stop(dir.root()), None, "a record past the cap");
        // A record that is not one is removed too, so it is not looked at again.
        Start::read(dir.root(), at());
        assert!(!dir.path(LAST_STOP).exists());
    }

    struct Answer(Result<String, String>);

    impl crate::install::Systemd for Answer {
        fn unavailable(&self) -> Option<String> {
            None
        }
        fn systemctl(&self, args: &[&str]) -> Result<String, String> {
            assert_eq!(
                args,
                [
                    "show",
                    "--property=NRestarts",
                    "--value",
                    "fleet-agent.service"
                ]
            );
            self.0.clone()
        }
    }

    #[test]
    fn restarts_is_systemds_count_or_an_error() {
        assert_eq!(restarts(&Answer(Ok("3".into()))), Ok(3));
        assert_eq!(restarts(&Answer(Ok("4294967295".into()))), Ok(u32::MAX));
        for bad in ["", "-1", "4294967296", "three"] {
            assert!(restarts(&Answer(Ok(bad.into()))).is_err(), "{bad:?}");
        }
        assert!(
            restarts(&Answer(Err("timed out".into())))
                .unwrap_err()
                .contains("timed out")
        );
    }

    #[test]
    fn note_stop_takes_only_a_config_path() {
        let parse = |args: &[&str]| {
            parse_args(
                std::iter::once(NOTE_STOP)
                    .chain(args.iter().copied())
                    .map(Into::into)
                    .collect(),
            )
        };
        assert_eq!(
            parse(&[]),
            Ok(std::path::PathBuf::from(crate::config::DEFAULT_CONFIG_PATH))
        );
        assert_eq!(
            parse(&["--config", "/tmp/a.toml"]),
            Ok(std::path::PathBuf::from("/tmp/a.toml"))
        );
        assert_eq!(
            parse(&["-c", "/tmp/a.toml"]),
            Ok(std::path::PathBuf::from("/tmp/a.toml"))
        );
        for bad in [
            &["--config"][..],
            &["--config="],
            &["-c", "/a", "-c", "/b"],
            &["run"],
            &["--recovery"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
