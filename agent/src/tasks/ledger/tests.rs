use std::cell::Cell;
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::test_support::{TempDir, mode, names};

thread_local! {
    /// Fail the n-th append from now (1 = the next one), on this thread.
    static FAIL_APPEND: Cell<Option<u32>> = const { Cell::new(None) };
}

/// Called before every append (tests only).
pub(super) fn fail_point() -> io::Result<()> {
    FAIL_APPEND.with(|fail| match fail.get() {
        Some(1) => {
            fail.set(None);
            Err(io::Error::from_raw_os_error(libc::ENOSPC))
        }
        Some(n) => {
            fail.set(Some(n - 1));
            Ok(())
        }
        None => Ok(()),
    })
}

fn fail_next_append() {
    FAIL_APPEND.with(|fail| fail.set(Some(1)));
}

const A: &str = "0b5c8a4e-1d6f-4a3b-9c2d-7e8f9a0b1c2d";
const B: &str = "1c6d9b5f-2e7a-4b4c-8d3e-8f9a0b1c2d3e";

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_767_268_800)
}

fn state() -> (TempDir, PathBuf) {
    let tmp = TempDir::new();
    let dir = tmp.path("state");
    crate::state::ensure_dir(&dir).unwrap();
    (tmp, dir)
}

fn open(dir: &Path) -> (Ledger, Recovery) {
    Ledger::open(dir, now()).unwrap()
}

fn receive(ledger: &mut Ledger, id: &str) -> Receipt {
    ledger
        .receive(
            id,
            "restart_service",
            1,
            300,
            &json!({"service": "nginx.service"}),
            now(),
        )
        .unwrap()
}

fn result(outcome: &str) -> Value {
    json!({"outcome": outcome, "output": "done\n"})
}

fn lines(dir: &Path) -> Vec<String> {
    fs::read_to_string(dir.join(LEDGER_FILE))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn state_of(ledger: &Ledger, id: &str) -> State {
    ledger.task(id).unwrap().state.clone()
}

#[test]
fn a_task_goes_through_every_step_and_each_is_on_disk_at_once() {
    let (_tmp, dir) = state();
    let (mut ledger, recovery) = open(&dir);
    assert_eq!(recovery, Recovery::default());
    assert_eq!(receive(&mut ledger, A), Receipt::New);
    // Each step is durable when the call returns: a fresh open (a crash right after) sees it.
    type Step<'a> = (&'a dyn Fn(&mut Ledger), State);
    let steps: [Step; 3] = [
        (&|l| l.start(A, now()).unwrap(), State::Started),
        (
            &|l| {
                l.finish(A, Outcome::Succeeded, None, &result("succeeded"), now())
                    .unwrap()
            },
            State::Finished {
                outcome: Outcome::Succeeded,
                reason: None,
            },
        ),
        (&|l| l.reported(A, false, now()).unwrap(), State::Reported),
    ];
    assert_eq!(state_of(&open_again(ledger, &dir), A), State::Received);
    let mut ledger = open(&dir).0;
    for (step, expected) in steps {
        step(&mut ledger);
        ledger = open_again(ledger, &dir);
        assert_eq!(state_of(&ledger, A), expected);
    }
    assert!(ledger.pending().is_empty());
    assert_eq!(lines(&dir).len(), 4);
    assert_eq!(mode(&dir.join(LEDGER_FILE)), 0o600);
    // The stored result is gone once reported.
    assert!(!dir.join(RESULT_FILE).exists());
}

/// Drops `ledger` (as a crash would: nothing more is written) and opens the file again.
fn open_again(ledger: Ledger, dir: &Path) -> Ledger {
    drop(ledger);
    open(dir).0
}

#[test]
fn a_known_id_is_never_received_or_started_again() {
    let (_tmp, dir) = state();
    let (mut ledger, _) = open(&dir);
    receive(&mut ledger, A);
    ledger.start(A, now()).unwrap();
    // Delivered again, in this process or after a restart: known, and it cannot start again.
    assert_eq!(receive(&mut ledger, A), Receipt::Known(State::Started));
    assert!(matches!(ledger.start(A, now()), Err(LedgerError::Step(_))));
    let mut ledger = open_again(ledger, &dir);
    assert_eq!(receive(&mut ledger, A), Receipt::Known(State::Started));
    assert!(matches!(ledger.start(A, now()), Err(LedgerError::Step(_))));
    // A task refused without starting cannot start later either.
    receive(&mut ledger, B);
    ledger
        .finish(
            B,
            Outcome::Refused,
            Some("not_supported"),
            &result("refused"),
            now(),
        )
        .unwrap();
    assert!(matches!(ledger.start(B, now()), Err(LedgerError::Step(_))));
    assert_eq!(
        receive(&mut ledger, B),
        Receipt::Known(State::Finished {
            outcome: Outcome::Refused,
            reason: Some("not_supported".into())
        })
    );
    // An id not received cannot start.
    assert!(matches!(
        ledger.start("2d7e0c6a-3f8b-4c5d-9e4f-9a0b1c2d3e4f", now()),
        Err(LedgerError::Step(_))
    ));
}

#[test]
fn only_task_ids_and_bounded_parameters_are_recorded() {
    let (_tmp, dir) = state();
    let (mut ledger, _) = open(&dir);
    for id in [
        "",
        "../../etc/passwd",
        "0B5C8A4E-1D6F-4A3B-9C2D-7E8F9A0B1C2D",
        "0b5c8a4e1d6f4a3b9c2d7e8f9a0b1c2d1234",
    ] {
        assert!(
            matches!(
                ledger.receive(id, "refresh_reports", 1, 600, &json!({}), now()),
                Err(LedgerError::Invalid(_))
            ),
            "{id}"
        );
    }
    let big = json!({"service": "x".repeat(MAX_PARAMETERS_BYTES)});
    assert!(matches!(
        ledger.receive(A, "restart_service", 1, 300, &big, now()),
        Err(LedgerError::Invalid(_))
    ));
    assert_eq!(ledger.len(), 0);
    assert_eq!(fs::read(dir.join(LEDGER_FILE)).unwrap(), b"");
}

#[test]
fn a_crash_after_finished_keeps_the_result_to_send_again() {
    let (_tmp, dir) = state();
    let (mut ledger, _) = open(&dir);
    receive(&mut ledger, A);
    ledger.start(A, now()).unwrap();
    ledger
        .finish(
            A,
            Outcome::Failed,
            Some("nonzero_exit"),
            &result("failed"),
            now(),
        )
        .unwrap();
    let ledger = open_again(ledger, &dir);
    assert_eq!(ledger.pending().len(), 1);
    assert_eq!(ledger.result(A), Some(result("failed")));
    assert_eq!(ledger.result(B), None);
    assert_eq!(mode(&dir.join(RESULT_FILE)), 0o600);
}

#[test]
fn a_torn_last_line_is_dropped_and_appends_continue_cleanly() {
    let (_tmp, dir) = state();
    let (mut ledger, _) = open(&dir);
    receive(&mut ledger, A);
    drop(ledger);
    // The `started` append was cut short: half a line, no newline.
    let mut file = OpenOptions::new()
        .append(true)
        .open(dir.join(LEDGER_FILE))
        .unwrap();
    file.write_all(b"0123456789abcdef {\"step\":\"sta").unwrap();
    drop(file);
    let (mut ledger, recovery) = open(&dir);
    assert!(recovery.torn_tail);
    assert_eq!(recovery.damaged, None);
    // The torn `started` never returned, so nothing ran: the task is only received, and not held.
    assert_eq!(state_of(&ledger, A), State::Received);
    assert!(!ledger.held(now()));
    assert_eq!(lines(&dir).len(), 1);
    ledger.start(A, now()).unwrap();
    let ledger = open_again(ledger, &dir);
    assert_eq!(state_of(&ledger, A), State::Started);
    assert_eq!(lines(&dir).len(), 2);
}

#[test]
fn a_whole_last_line_without_its_newline_is_believed() {
    let (_tmp, dir) = state();
    let (mut ledger, _) = open(&dir);
    receive(&mut ledger, A);
    ledger.start(A, now()).unwrap();
    drop(ledger);
    // The newline of `started` did not reach the disk; the record itself did.
    let path = dir.join(LEDGER_FILE);
    let bytes = fs::read(&path).unwrap();
    fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
    let (ledger, recovery) = open(&dir);
    assert!(recovery.torn_tail);
    assert_eq!(state_of(&ledger, A), State::Started);
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn a_bad_last_line_with_its_newline_is_damage_not_a_torn_tail() {
    // Review of #166: a whole line was written in one append, or by compaction, so it may have been
    // acted on.
    let (_tmp, dir) = state();
    let (mut ledger, _) = open(&dir);
    receive(&mut ledger, A);
    drop(ledger);
    let path = dir.join(LEDGER_FILE);
    let mut bytes = fs::read(&path).unwrap();
    bytes.extend_from_slice(b"\x00\x00\x00garbage\n");
    fs::write(&path, &bytes).unwrap();
    let (ledger, recovery) = open(&dir);
    assert!(!recovery.torn_tail);
    assert!(recovery.damaged.unwrap().contains("line 2"));
    assert!(ledger.held(now()));
    assert_eq!(state_of(&ledger, A), State::Received);
}

#[test]
fn a_crash_while_setting_a_damaged_ledger_aside_still_holds_and_keeps_the_records() {
    // Review of #166: stopped after the rename and before the replacement was written.
    let (_tmp, dir) = state();
    let (mut ledger, _) = open(&dir);
    receive(&mut ledger, A);
    ledger.start(A, now()).unwrap();
    drop(ledger);
    fs::rename(dir.join(LEDGER_FILE), dir.join(DAMAGED_FILE)).unwrap();
    let (mut ledger, recovery) = open(&dir);
    assert!(
        recovery
            .damaged
            .unwrap()
            .contains("missing beside a damaged copy")
    );
    assert!(ledger.held(now()));
    assert_eq!(state_of(&ledger, A), State::Started);
    assert_eq!(receive(&mut ledger, A), Receipt::Known(State::Started));
    // The copy stays for inspection; the new ledger holds the records and the hold.
    assert!(dir.join(DAMAGED_FILE).exists());
    let ledger = open_again(ledger, &dir);
    assert!(ledger.held(now()));
    assert_eq!(state_of(&ledger, A), State::Started);
}

#[test]
fn another_tasks_stored_result_is_never_overwritten() {
    // Review of #166: after damage, an older unfinished task must not take a later one's result.
    let (_tmp, dir) = state();
    let (mut ledger, _) = open(&dir);
    receive(&mut ledger, A);
    receive(&mut ledger, B);
    ledger
        .finish(B, Outcome::Succeeded, None, &result("succeeded"), now())
        .unwrap();
    assert_eq!(ledger.result_owner().as_deref(), Some(B));
    assert!(matches!(
        ledger.finish(
            A,
            Outcome::Failed,
            Some("interrupted"),
            &result("failed"),
            now()
        ),
        Err(LedgerError::Step(_))
    ));
    assert!(matches!(
        ledger.store_result(A, &result("failed")),
        Err(LedgerError::Step(_))
    ));
    assert_eq!(ledger.result(B), Some(result("succeeded")));
    ledger.reported(B, false, now()).unwrap();
    assert_eq!(ledger.result_owner(), None);
    ledger
        .finish(
            A,
            Outcome::Failed,
            Some("interrupted"),
            &result("failed"),
            now(),
        )
        .unwrap();
    // A result stored for a finished task is the one later reads return.
    let rebuilt = json!({"outcome": "failed", "report_id": "r"});
    ledger.store_result(A, &rebuilt).unwrap();
    assert_eq!(ledger.result(A), Some(rebuilt));
}

#[test]
fn damage_before_the_last_line_keeps_what_is_readable_and_holds_every_task() {
    let (_tmp, dir) = state();
    let (mut ledger, _) = open(&dir);
    receive(&mut ledger, A);
    ledger.start(A, now()).unwrap();
    ledger
        .finish(A, Outcome::Succeeded, None, &result("succeeded"), now())
        .unwrap();
    ledger.reported(A, false, now()).unwrap();
    receive(&mut ledger, B);
    drop(ledger);
    let path = dir.join(LEDGER_FILE);
    let original = fs::read_to_string(&path).unwrap();
    // Flip one character inside the second line (A's `started`); later lines follow it.
    let mut damaged: Vec<String> = original.lines().map(str::to_owned).collect();
    damaged[1] = damaged[1].replacen("started", "stArted", 1);
    let damaged = damaged.join("\n") + "\n";
    fs::write(&path, &damaged).unwrap();

    let (mut ledger, recovery) = open(&dir);
    let why = recovery.damaged.unwrap();
    assert!(why.contains("line 2"), "{why}");
    // The damaged file is kept as it was, for inspection.
    assert_eq!(fs::read_to_string(dir.join(DAMAGED_FILE)).unwrap(), damaged);
    // Readable records stay: A is still reported, B still only received.
    assert_eq!(state_of(&ledger, A), State::Reported);
    assert_eq!(state_of(&ledger, B), State::Received);
    // Nothing may start during the hold, which outlives a restart and ends after the longest a task
    // can wait and run.
    assert!(ledger.held(now()));
    assert!(matches!(ledger.start(B, now()), Err(LedgerError::Step(_))));
    let until = ledger.hold_until(now()).unwrap();
    assert_eq!(until, unix(now()) + hold_seconds());
    assert_eq!(hold_seconds(), 86_400 + 3_600);
    let ledger = open_again(ledger, &dir);
    assert!(ledger.held(now()));
    let later = UNIX_EPOCH + Duration::from_secs(until);
    assert!(!ledger.held(later));
    assert_eq!(ledger.hold_until(later), None);
    let mut ledger = open_again(ledger, &dir);
    // After the hold, a task received during it still cannot start (it is in the ledger), but new
    // ones can.
    receive(&mut ledger, "2d7e0c6a-3f8b-4c5d-9e4f-9a0b1c2d3e4f");
    ledger
        .start("2d7e0c6a-3f8b-4c5d-9e4f-9a0b1c2d3e4f", later)
        .unwrap();
}

#[test]
fn an_unreadable_ledger_is_set_aside_under_a_hold() {
    let (_tmp, dir) = state();
    let path = dir.join(LEDGER_FILE);
    // Too large to read.
    fs::write(&path, vec![b'x'; MAX_LEDGER_BYTES as usize + 1]).unwrap();
    let (ledger, recovery) = open(&dir);
    assert!(recovery.damaged.unwrap().contains("cannot be read"));
    assert!(ledger.held(now()));
    assert_eq!(ledger.len(), 0);
    assert_eq!(
        fs::metadata(dir.join(DAMAGED_FILE)).unwrap().len(),
        MAX_LEDGER_BYTES + 1
    );
    drop(ledger);
    // A symlink planted in its place is set aside, never followed.
    let target = dir.join("target");
    fs::write(&target, "untouched").unwrap();
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let (ledger, recovery) = open(&dir);
    assert!(recovery.damaged.is_some());
    assert!(ledger.held(now()));
    assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
    assert!(
        fs::symlink_metadata(dir.join(DAMAGED_FILE))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(fs::symlink_metadata(&path).unwrap().is_file());
}

#[test]
fn a_record_from_a_newer_version_is_an_unknown_state_never_a_start() {
    let (_tmp, dir) = state();
    let (mut ledger, _) = open(&dir);
    receive(&mut ledger, A);
    drop(ledger);
    // A step this version does not know, correctly summed.
    let json = format!(r#"{{"step":"acknowledged","task_id":"{A}","at":"2026-01-01T12:00:00Z"}}"#);
    let mut file = OpenOptions::new()
        .append(true)
        .open(dir.join(LEDGER_FILE))
        .unwrap();
    writeln!(file, "{} {json}", sum(json.as_bytes())).unwrap();
    // And one that names no task: damage only if lines follow it; here it is the last, so torn.
    drop(file);
    let (mut ledger, recovery) = open(&dir);
    assert_eq!(recovery.unknown_records, 1);
    assert_eq!(recovery.damaged, None);
    assert_eq!(state_of(&ledger, A), State::Unknown);
    assert!(matches!(ledger.start(A, now()), Err(LedgerError::Step(_))));
    assert_eq!(receive(&mut ledger, A), Receipt::Known(State::Unknown));
    // It can still be reported.
    ledger
        .finish(
            A,
            Outcome::Failed,
            Some("agent_error"),
            &result("failed"),
            now(),
        )
        .unwrap();
    ledger.reported(A, false, now()).unwrap();
    assert!(ledger.pending().is_empty());
}

#[test]
fn a_failed_append_poisons_the_ledger_until_it_is_opened_again() {
    let (_tmp, dir) = state();
    let (mut ledger, _) = open(&dir);
    receive(&mut ledger, A);
    fail_next_append();
    assert!(matches!(ledger.start(A, now()), Err(LedgerError::Io(_))));
    assert!(matches!(ledger.start(A, now()), Err(LedgerError::Poisoned)));
    assert!(matches!(
        ledger.receive(B, "refresh_reports", 1, 600, &json!({}), now()),
        Err(LedgerError::Poisoned)
    ));
    // The file says what is durable: the start never reached it.
    let mut ledger = open_again(ledger, &dir);
    assert_eq!(state_of(&ledger, A), State::Received);
    ledger.start(A, now()).unwrap();
}

#[test]
fn a_second_process_cannot_open_the_ledger() {
    let (_tmp, dir) = state();
    let (ledger, _) = open(&dir);
    assert!(matches!(
        Ledger::open(&dir, now()),
        Err(LedgerError::Locked)
    ));
    drop(ledger);
    assert!(Ledger::open(&dir, now()).is_ok());
}

/// Fills the ledger with `count` reported tasks with sequential ids.
fn fill(ledger: &mut Ledger, from: usize, count: usize) -> Vec<String> {
    let mut ids = Vec::new();
    for n in from..from + count {
        let id = format!("00000000-0000-4000-8000-{n:012x}");
        ledger
            .receive(&id, "refresh_reports", 1, 600, &json!({}), now())
            .unwrap();
        ledger
            .finish(
                &id,
                Outcome::Refused,
                Some("not_supported"),
                &json!({}),
                now(),
            )
            .unwrap();
        ledger.reported(&id, false, now()).unwrap();
        ids.push(id);
    }
    ids
}

#[test]
fn compaction_bounds_the_file_and_keeps_the_latest_ids() {
    let (_tmp, dir) = state();
    let (mut ledger, _) = open(&dir);
    let ids = fill(&mut ledger, 0, 1500);
    assert!(ledger.bytes() < MAX_LEDGER_BYTES);
    // Compaction ran on the way (each task is about 400 bytes, so 1500 pass COMPACT_AT_BYTES).
    assert!(ledger.len() <= KEEP_DONE + 1000);
    let ledger = open_again(ledger, &dir);
    // The newest ids are all still known, so none of them can run again.
    for id in &ids[ids.len() - KEEP_DONE..] {
        assert_eq!(state_of(&ledger, id), State::Reported, "{id}");
    }
    assert!(ledger.bytes() < COMPACT_AT_BYTES + 16 * 1024);
    assert_eq!(
        names(&dir),
        [LEDGER_FILE, LOCK_FILE],
        "no temporary or result file left"
    );
}

#[test]
fn compaction_keeps_every_id_reported_within_the_hold_window() {
    // Review of #166: an id stays known for as long as the server could still deliver it.
    let (_tmp, dir) = state();
    let (mut ledger, _) = open(&dir);
    let ids = fill(&mut ledger, 0, KEEP_DONE + 200);
    // All were reported "now", so compaction keeps every one of them.
    ledger.compact(now()).unwrap();
    assert_eq!(ledger.len(), KEEP_DONE + 200);
    // Once they are older than the hold, only the last KEEP_DONE stay.
    let later = now() + Duration::from_secs(hold_seconds() + 1);
    ledger.compact(later).unwrap();
    assert_eq!(ledger.len(), KEEP_DONE);
    let ledger = open_again(ledger, &dir);
    assert!(ledger.task(&ids[199]).is_none());
    assert_eq!(state_of(&ledger, &ids[200]), State::Reported);
    // Compaction kept each id's own reported time, not the time it ran.
    assert!(lines(&dir)[0].contains("2026-01-01T12:00:00.000Z"));
}

#[test]
fn compaction_waits_for_an_unreported_task_and_a_full_ledger_takes_nothing_more() {
    let (_tmp, dir) = state();
    let (mut ledger, _) = open(&dir);
    fill(&mut ledger, 0, 10);
    receive(&mut ledger, A);
    // Pad the file past the hard limit's reserve with reported tasks recorded directly.
    let pad = line(&Entry::Done {
        task_id: B.into(),
        outcome: None,
        at: "x".repeat(MAX_RECORD_BYTES - 200),
    })
    .unwrap();
    while ledger.bytes() + pad.len() as u64 + RESERVE_BYTES < MAX_LEDGER_BYTES {
        ledger.append(&pad).unwrap();
    }
    let small = line(&Entry::Done {
        task_id: B.into(),
        outcome: None,
        at: "t".into(),
    })
    .unwrap();
    // Until the next receive would not leave the reserve free.
    let want = line(&Entry::Received {
        task_id: A.into(),
        task_type: "refresh_reports".into(),
        catalog_version: 1,
        timeout_seconds: 600,
        parameters: json!({}),
        at: rfc3339(now()),
    })
    .unwrap()
    .len() as u64;
    while ledger.bytes() + want + RESERVE_BYTES <= MAX_LEDGER_BYTES {
        ledger.append(&small).unwrap();
    }
    // A is unreported, so the ledger cannot be compacted, and it takes no new task.
    assert!(matches!(
        ledger.receive(
            "2d7e0c6a-3f8b-4c5d-9e4f-9a0b1c2d3e4f",
            "refresh_reports",
            1,
            600,
            &json!({}),
            now()
        ),
        Err(LedgerError::Full)
    ));
    // A can still finish and be reported in the reserved room; then compaction makes room again.
    ledger.start(A, now()).unwrap();
    ledger
        .finish(A, Outcome::Succeeded, None, &result("succeeded"), now())
        .unwrap();
    ledger.reported(A, false, now()).unwrap();
    assert_eq!(
        ledger
            .receive(
                "2d7e0c6a-3f8b-4c5d-9e4f-9a0b1c2d3e4f",
                "refresh_reports",
                1,
                600,
                &json!({}),
                now()
            )
            .unwrap(),
        Receipt::New
    );
    assert!(ledger.bytes() < COMPACT_AT_BYTES);
    assert_eq!(state_of(&ledger, A), State::Reported);
}

#[test]
fn compaction_keeps_a_hold_in_force() {
    let (_tmp, dir) = state();
    let (mut ledger, _) = open(&dir);
    fill(&mut ledger, 0, 3);
    drop(ledger);
    let path = dir.join(LEDGER_FILE);
    let mut text: Vec<String> = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    text[0].insert(20, 'x');
    fs::write(&path, text.join("\n") + "\n").unwrap();
    let (mut ledger, _) = open(&dir);
    assert!(ledger.held(now()));
    ledger.compact(now()).unwrap();
    let ledger = open_again(ledger, &dir);
    assert!(ledger.held(now()));
}

#[test]
fn records_are_summed_lines_of_json() {
    let (_tmp, dir) = state();
    let (mut ledger, _) = open(&dir);
    receive(&mut ledger, A);
    let text = &lines(&dir)[0];
    let (digits, json) = text.split_once(' ').unwrap();
    assert_eq!(digits, sum(json.as_bytes()));
    let value: Value = serde_json::from_str(json).unwrap();
    assert_eq!(
        value,
        json!({
            "step": "received",
            "task_id": A,
            "task_type": "restart_service",
            "catalog_version": 1,
            "timeout_seconds": 300,
            "parameters": {"service": "nginx.service"},
            "at": "2026-01-01T12:00:00.000Z",
        })
    );
    // A known step with an extra field is not silently read as the step.
    let extra =
        r#"{"step":"started","task_id":"0b5c8a4e-1d6f-4a3b-9c2d-7e8f9a0b1c2d","at":"t","x":1}"#;
    let mut raw = sum(extra.as_bytes()).into_bytes();
    raw.push(b' ');
    raw.extend_from_slice(extra.as_bytes());
    assert!(matches!(parse_line(&raw), Some(Parsed::Unknown(_))));
}
