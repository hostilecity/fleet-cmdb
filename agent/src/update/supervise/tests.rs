//! Supervisor tests: the whole life of an update against a fake machine, and each way it can end or be
//! interrupted. Releases are signed with throwaway keys generated here; nothing is checked in.

use std::fs;

use super::*;
use crate::update::layout::{LOCK_FILE, MARKER_FILE};
use crate::update::record::{Marker, PendingResult, Phase, Record};
use crate::update::stage::tests::binary;
use crate::update::supervise::{Ended, Intent};
use crate::update::tests::{Agent, NEW, World, old};

const NEW_BODY_LEN: usize = 30_000;

fn staged(world: &World) -> Record {
    world.stage_release(NEW, &binary(NEW_BODY_LEN), 5)
}

#[test]
fn an_update_the_new_version_confirms_is_installed_kept_and_reported() {
    let world = World::new();
    // An older version left from before: only two versions are kept.
    fs::create_dir_all(world.layout.version_dir("0.0.1")).unwrap();
    let record = staged(&world);

    assert_eq!(world.run(Intent::Resume), Ok(Ended::Confirmed));

    assert_eq!(world.current().as_deref(), Some(NEW));
    assert_eq!(world.previous().as_deref(), Some(old()));
    assert_eq!(
        fs::read(world.layout.binary(NEW)).unwrap(),
        binary(NEW_BODY_LEN)
    );
    let mode = fs::metadata(world.layout.binary(NEW))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o755);
    assert!(
        world.layout.binary(old()).is_file(),
        "the previous version is kept"
    );
    assert!(
        !world.layout.version_dir("0.0.1").exists(),
        "older ones are removed"
    );
    // One restart, into the new version; the outcome is left for the agent to send.
    assert_eq!(world.systemd.restarts(), 1);
    let result = world.pending().unwrap();
    assert_eq!(result.outcome, Outcome::Succeeded);
    assert_eq!(result.report_id, record.report_id);
    assert_eq!((result.rollout_id, result.version.as_str()), (5, NEW));
    assert_eq!(result.reason, None);
    // The credential and state are untouched, the update is over, and nothing is left behind.
    assert_eq!(
        world.inventory(),
        r#"{"v":"new"}"#,
        "the new version's state is kept"
    );
    assert!(Record::read(world.state()).unwrap().is_none());
    assert!(!world.layout.staging(NEW).exists() && !world.layout.backup_dir().exists());
    assert!(!world.state().join(MARKER_FILE).exists());
}

#[test]
fn a_release_that_exits_at_start_is_rolled_back_and_reported() {
    let world = World::new();
    world.behaves(NEW, Agent::Fails);
    staged(&world);

    assert_eq!(world.run(Intent::Resume), Ok(Ended::RolledBack));

    assert_eq!(world.current().as_deref(), Some(old()));
    assert!(
        !world.layout.version_dir(NEW).exists(),
        "the failed version is removed"
    );
    // Restarted into the new version, then back into the old one (after clearing the failed state).
    assert_eq!(world.systemd.restarts(), 2);
    assert_eq!(
        world.systemd.calls.borrow().first().map(String::as_str),
        Some("reset-failed")
    );
    let result = world.pending().unwrap();
    assert_eq!(result.outcome, Outcome::RolledBack);
    assert!(
        result
            .reason
            .unwrap()
            .contains("failed to start or kept failing")
    );
    assert!(Record::read(world.state()).unwrap().is_none());
    assert_eq!(
        world.inventory(),
        r#"{"v":"old"}"#,
        "the state the old version last saw is back"
    );
}

#[test]
fn a_release_that_cannot_authenticate_is_rolled_back_at_the_deadline() {
    let world = World::new();
    world.behaves(NEW, Agent::Silent);
    let record = staged(&world);
    let started = world.clock.0.get();

    assert_eq!(world.run(Intent::Resume), Ok(Ended::RolledBack));

    assert_eq!(world.current().as_deref(), Some(old()));
    let waited = world.clock.0.get() - started;
    assert!(
        (record.confirm_seconds..record.confirm_seconds + 5).contains(&waited),
        "waited {waited} s"
    );
    let result = world.pending().unwrap();
    assert_eq!(result.outcome, Outcome::RolledBack);
    assert!(
        result
            .reason
            .unwrap()
            .contains("no acknowledged heartbeat from the new version within 300 seconds")
    );
}

#[test]
fn a_service_that_cannot_be_restarted_is_rolled_back() {
    let world = World::new();
    staged(&world);
    world.systemd.fail_restart.set(true);
    // The restart into the new version fails; so does the one back, which leaves the update unfinished
    // for the next supervisor (nothing is reported as done).
    assert!(world.run(Intent::Resume).is_err());
    assert_eq!(
        world.current().as_deref(),
        Some(old()),
        "`current` is back before the restart"
    );
    let record = Record::read(world.state()).unwrap().unwrap();
    assert_eq!(record.phase, Phase::RollingBack);
    world.systemd.fail_restart.set(false);
    assert_eq!(world.run(Intent::Resume), Ok(Ended::RolledBack));
    assert_eq!(world.pending().unwrap().outcome, Outcome::RolledBack);
    assert!(Record::read(world.state()).unwrap().is_none());
}

#[test]
fn a_staged_release_that_no_longer_verifies_is_refused_before_anything_changes() {
    let world = World::new();
    staged(&world);
    // Changed in the staging directory after the agent checked it.
    let mut evil = binary(NEW_BODY_LEN);
    evil[3] ^= 0xff;
    fs::write(world.layout.staging(NEW).join("fleet-agent"), evil).unwrap();

    assert_eq!(world.run(Intent::Resume), Ok(Ended::Failed));

    assert_eq!(world.current().as_deref(), Some(old()));
    assert_eq!(world.systemd.restarts(), 0);
    let result = world.pending().unwrap();
    assert_eq!(result.outcome, Outcome::Failed);
    assert!(result.reason.unwrap().contains("SHA-256"));
    assert!(!world.layout.version_dir(NEW).exists());
    assert!(Record::read(world.state()).unwrap().is_none());
}

#[test]
fn a_staged_release_signed_by_another_key_is_refused_by_the_supervisor_too() {
    let world = World::new();
    let other = crate::update::stage::tests::TestKey::generate();
    let record = staged(&world);
    let dir = world.layout.staging(&record.version);
    let manifest = fs::read(dir.join("manifest.json")).unwrap();
    fs::write(dir.join("manifest.json.minisig"), other.sign(&manifest)).unwrap();
    assert_eq!(world.run(Intent::Resume), Ok(Ended::Failed));
    assert!(
        world
            .pending()
            .unwrap()
            .reason
            .unwrap()
            .contains("does not trust")
    );
    assert_eq!(world.current().as_deref(), Some(old()));
}

#[test]
fn a_supervisor_that_is_not_the_version_being_replaced_refuses() {
    let world = World::new();
    let mut record = staged(&world);
    record.from_version = "0.0.5".into();
    record.write(world.state()).unwrap();
    let error = world.run(Intent::Resume).unwrap_err();
    assert!(
        error.contains("must run from the version being replaced"),
        "{error}"
    );
    assert_eq!(world.current().as_deref(), Some(old()));
}

#[test]
fn only_one_supervisor_runs_at_a_time() {
    let world = World::new();
    staged(&world);
    let _held = Lock::file(&world.state().join(LOCK_FILE)).unwrap().unwrap();
    assert_eq!(world.run(Intent::Resume), Ok(Ended::Busy));
    assert_eq!(world.systemd.restarts(), 0);
}

#[test]
fn nothing_happens_without_an_update() {
    let world = World::new();
    assert_eq!(world.run(Intent::Resume), Ok(Ended::NothingToDo));
    assert_eq!(world.run(Intent::Rollback("x")), Ok(Ended::NothingToDo));
}

// --- Interrupted supervisors -----------------------------------------------------------------------

#[test]
fn a_supervisor_killed_after_the_switch_is_resumed_and_the_new_version_wins() {
    let world = World::new();
    staged(&world);
    // The first supervisor got as far as swapping `current` and recording it, then died.
    let mut record = Record::read(world.state()).unwrap().unwrap();
    fs::create_dir_all(world.layout.version_dir(NEW)).unwrap();
    fs::copy(
        world.layout.staging(NEW).join("fleet-agent"),
        world.layout.binary(NEW),
    )
    .unwrap();
    crate::fsx::replace_symlink(&world.layout.previous(), &Path::new("versions").join(old()))
        .unwrap();
    crate::fsx::replace_symlink(&world.layout.current(), &Path::new("versions").join(NEW)).unwrap();
    record.phase = Phase::Switched;
    record.write(world.state()).unwrap();

    assert_eq!(world.run(Intent::Resume), Ok(Ended::Confirmed));
    // It had not restarted yet, so the resumed supervisor restarted exactly once.
    assert_eq!(world.systemd.restarts(), 1);
    assert_eq!(world.current().as_deref(), Some(NEW));
    assert_eq!(world.pending().unwrap().outcome, Outcome::Succeeded);
}

#[test]
fn a_supervisor_killed_between_the_swap_and_the_record_is_resumed() {
    let world = World::new();
    staged(&world);
    // `current` was swapped, but the record still says Staged.
    fs::create_dir_all(world.layout.version_dir(NEW)).unwrap();
    fs::copy(
        world.layout.staging(NEW).join("fleet-agent"),
        world.layout.binary(NEW),
    )
    .unwrap();
    crate::fsx::replace_symlink(&world.layout.current(), &Path::new("versions").join(NEW)).unwrap();
    assert_eq!(world.run(Intent::Resume), Ok(Ended::Confirmed));
    assert_eq!(world.current().as_deref(), Some(NEW));
}

#[test]
fn a_supervisor_killed_before_the_switch_starts_over_and_still_ends_with_one_version() {
    let world = World::new();
    staged(&world);
    // It was killed after writing the Switching phase and installing the binary, before the swap.
    let mut record = Record::read(world.state()).unwrap().unwrap();
    record.phase = Phase::Switching;
    record.write(world.state()).unwrap();
    fs::create_dir_all(world.layout.version_dir(NEW)).unwrap();
    assert_eq!(world.current().as_deref(), Some(old()));
    assert_eq!(world.run(Intent::Resume), Ok(Ended::Confirmed));
    assert_eq!(world.current().as_deref(), Some(NEW));
    assert!(world.layout.binary(NEW).is_file());
}

/// A marker for the staged update, written in the current boot at `unix`.
fn marker(world: &World, unix: u64) -> Marker {
    Marker {
        rollout_id: 5,
        version: NEW.into(),
        pid: 1,
        confirmed_at: "2026-01-01T12:00:00Z".into(),
        confirmed_unix: unix,
        boot_id: world.systemd.boot.borrow().clone(),
    }
}

/// The supervisor restarted the service into the new version 60 s ago and then died.
fn switched_and_restarted(world: &World) -> Record {
    let mut record = staged(world);
    fs::create_dir_all(world.layout.version_dir(NEW)).unwrap();
    fs::copy(
        world.layout.staging(NEW).join("fleet-agent"),
        world.layout.binary(NEW),
    )
    .unwrap();
    crate::fsx::replace_symlink(&world.layout.previous(), &Path::new("versions").join(old()))
        .unwrap();
    crate::fsx::replace_symlink(&world.layout.current(), &Path::new("versions").join(NEW)).unwrap();
    record.phase = Phase::Switched;
    record.restarted = true;
    record.deadline_unix = Some(world.clock.0.get() + 240);
    record.write(world.state()).unwrap();
    record
}

#[test]
fn an_update_the_vm_restarted_under_is_rolled_back_even_if_the_new_version_then_confirms() {
    // ADR 0018 and FR-S.5: if the VM restarts before the update is confirmed, the agent returns to
    // the previous version. The new version, started by systemd at boot, does not confirm it, and a
    // marker it might have written in the new boot does not count.
    let world = World::new();
    switched_and_restarted(&world);
    world.reboot();
    marker(&world, world.clock.0.get())
        .write(world.state())
        .unwrap();
    assert_eq!(world.run(Intent::Resume), Ok(Ended::RolledBack));
    assert_eq!(world.current().as_deref(), Some(old()));
    let result = world.pending().unwrap();
    assert_eq!(result.outcome, Outcome::RolledBack);
    assert!(result.reason.unwrap().contains("restarted"));
    assert_eq!(world.inventory(), r#"{"v":"old"}"#, "the state is restored");
}

#[test]
fn an_update_confirmed_before_the_vm_restarted_is_kept() {
    let world = World::new();
    switched_and_restarted(&world);
    marker(&world, world.clock.0.get())
        .write(world.state())
        .unwrap();
    world.reboot();
    assert_eq!(world.run(Intent::Resume), Ok(Ended::Confirmed));
    assert_eq!(world.current().as_deref(), Some(NEW));
}

#[test]
fn an_update_the_vm_restarted_under_before_the_switch_is_reported_failed() {
    let world = World::new();
    staged(&world);
    world.reboot();
    assert_eq!(world.run(Intent::Resume), Ok(Ended::Failed));
    assert_eq!(world.current().as_deref(), Some(old()));
    assert_eq!(world.systemd.restarts(), 0);
    assert!(Record::read(world.state()).unwrap().is_none());
    assert!(
        world
            .pending()
            .unwrap()
            .reason
            .unwrap()
            .contains("restarted")
    );
}

#[test]
fn a_confirmation_after_the_deadline_is_not_success() {
    // The supervisor died; the new version's first acknowledged heartbeat came after the deadline
    // (an authentication backoff, say). The supervisor that resumes rolls back.
    let world = World::new();
    world.behaves(NEW, Agent::Silent);
    let record = switched_and_restarted(&world);
    let deadline = record.deadline_unix.unwrap();
    world.clock.0.set(deadline + 120);
    marker(&world, deadline + 1).write(world.state()).unwrap();
    assert_eq!(world.run(Intent::Resume), Ok(Ended::RolledBack));
    assert_eq!(world.current().as_deref(), Some(old()));
    // On time, it is success, whenever the supervisor reads it.
    let world = World::new();
    let record = switched_and_restarted(&world);
    let deadline = record.deadline_unix.unwrap();
    world.clock.0.set(deadline + 120);
    marker(&world, deadline).write(world.state()).unwrap();
    assert_eq!(world.run(Intent::Resume), Ok(Ended::Confirmed));
}

#[test]
fn a_day_old_update_is_failed_before_the_switch_and_rolled_back_after_it_never_dropped() {
    // Before the switch: nothing is selected, so it is reported failed and cleared.
    let world = World::new();
    staged(&world);
    world
        .clock
        .0
        .set(world.clock.0.get() + STALE_AFTER.as_secs() + 1);
    assert_eq!(world.run(Intent::Resume), Ok(Ended::Failed));
    assert_eq!(world.current().as_deref(), Some(old()));
    // After the switch: the unconfirmed new version is never left selected.
    let world = World::new();
    world.behaves(NEW, Agent::Silent);
    switched_and_restarted(&world);
    world
        .clock
        .0
        .set(world.clock.0.get() + STALE_AFTER.as_secs() + 1);
    assert_eq!(world.run(Intent::Resume), Ok(Ended::RolledBack));
    assert_eq!(world.current().as_deref(), Some(old()));
}

#[test]
fn the_new_version_is_stopped_before_the_state_is_restored() {
    // The new version is running and still saving state when the rollback begins; it must not be able
    // to overwrite what the rollback restores.
    let world = World::new();
    world.behaves(NEW, Agent::Silent);
    staged(&world);
    assert_eq!(world.run(Intent::Resume), Ok(Ended::RolledBack));
    assert_eq!(world.inventory(), r#"{"v":"old"}"#);
    let calls = world.systemd.calls.borrow().clone();
    let stop = calls.iter().position(|c| c == "stop").expect("stopped");
    let last_restart = calls.iter().rposition(|c| c == "restart").unwrap();
    assert!(stop < last_restart, "{calls:?}");
}

fn rename_then_fail(link: &Path, target: &Path) -> io::Result<()> {
    crate::fsx::replace_symlink(link, target)?;
    Err(io::Error::other("fsync of /usr/lib/fleet-agent failed"))
}

#[test]
fn a_switch_that_took_effect_despite_an_error_is_handled_as_switched() {
    // The rename of `current` succeeded and syncing its directory failed: the new version is selected,
    // so the update goes on as a switched one (confirmed here), not cleaned up as a failed switch.
    let world = World::new();
    staged(&world);
    world.swap_current.set(rename_then_fail);
    assert_eq!(world.run(Intent::Resume), Ok(Ended::Confirmed));
    assert_eq!(world.current().as_deref(), Some(NEW));
    assert_eq!(world.pending().unwrap().outcome, Outcome::Succeeded);
    // And when it does not confirm, it is rolled back from the new version.
    let world = World::new();
    world.behaves(NEW, Agent::Silent);
    staged(&world);
    world.swap_current.set(rename_then_fail);
    assert_eq!(world.run(Intent::Resume), Ok(Ended::RolledBack));
    assert_eq!(world.current().as_deref(), Some(old()));
}

#[test]
fn a_resumed_supervisor_rolls_back_at_the_recorded_deadline() {
    let world = World::new();
    world.behaves(NEW, Agent::Silent);
    staged(&world);
    let mut record = Record::read(world.state()).unwrap().unwrap();
    fs::create_dir_all(world.layout.version_dir(NEW)).unwrap();
    fs::copy(
        world.layout.staging(NEW).join("fleet-agent"),
        world.layout.binary(NEW),
    )
    .unwrap();
    crate::fsx::replace_symlink(&world.layout.current(), &Path::new("versions").join(NEW)).unwrap();
    record.phase = Phase::Switched;
    record.restarted = true;
    record.deadline_unix = Some(world.clock.0.get() - 1); // long past
    record.write(world.state()).unwrap();
    assert_eq!(world.run(Intent::Resume), Ok(Ended::RolledBack));
    assert_eq!(world.current().as_deref(), Some(old()));
    assert_eq!(
        world.systemd.restarts(),
        1,
        "only the restart back into the old version"
    );
}

#[test]
fn a_rollback_killed_halfway_is_finished_by_the_next_supervisor_with_the_same_report_id() {
    let world = World::new();
    world.behaves(NEW, Agent::Fails);
    let record = staged(&world);
    assert_eq!(world.run(Intent::Resume), Ok(Ended::RolledBack));
    let first = world.pending().unwrap();

    // Again, but put the machine back as it is when the rollback died after reporting and before
    // the clean-up: the record says RollingBack, `current` is the old version.
    let world = World::new();
    staged(&world);
    let mut rec = Record::read(world.state()).unwrap().unwrap();
    rec.phase = Phase::RollingBack;
    rec.rollback_reason = Some("the new version failed to start".into());
    rec.write(world.state()).unwrap();
    assert_eq!(world.run(Intent::Resume), Ok(Ended::RolledBack));
    let second = world.pending().unwrap();
    assert_eq!(first.report_id, record.report_id);
    assert_eq!(second.report_id, record.report_id);
    assert_eq!(world.current().as_deref(), Some(old()));
}

// --- The OnFailure rollback --------------------------------------------------------------------------

fn switched_unconfirmed(world: &World) {
    let mut record = staged(world);
    fs::create_dir_all(world.layout.version_dir(NEW)).unwrap();
    fs::copy(
        world.layout.staging(NEW).join("fleet-agent"),
        world.layout.binary(NEW),
    )
    .unwrap();
    crate::fsx::replace_symlink(&world.layout.previous(), &Path::new("versions").join(old()))
        .unwrap();
    crate::fsx::replace_symlink(&world.layout.current(), &Path::new("versions").join(NEW)).unwrap();
    record.phase = Phase::Switched;
    record.restarted = true;
    record.deadline_unix = Some(world.clock.0.get() + 100_000);
    record.write(world.state()).unwrap();
}

#[test]
fn a_crash_loop_with_a_dead_supervisor_is_rolled_back_by_the_failure_hook() {
    let world = World::new();
    world.behaves(NEW, Agent::Fails);
    switched_unconfirmed(&world);
    assert_eq!(
        world.run(Intent::Rollback("the new version kept failing")),
        Ok(Ended::RolledBack)
    );
    assert_eq!(world.current().as_deref(), Some(old()));
    let result = world.pending().unwrap();
    assert_eq!(result.outcome, Outcome::RolledBack);
    assert!(result.reason.unwrap().contains("kept failing"));
    assert!(!world.layout.version_dir(NEW).exists());
}

/// `switched_unconfirmed` with a deadline `seconds` from now. Returns the deadline.
fn switched_unconfirmed_due_in(world: &World, seconds: u64) -> u64 {
    switched_unconfirmed(world);
    let mut record = Record::read(world.state()).unwrap().unwrap();
    let deadline = world.clock.0.get() + seconds;
    record.deadline_unix = Some(deadline);
    record.write(world.state()).unwrap();
    deadline
}

fn hold_lock(world: &World) -> Lock {
    Lock::file(&world.state().join(LOCK_FILE)).unwrap().unwrap()
}

#[test]
fn the_failure_hook_waits_for_the_lock_and_rolls_back_once_the_supervisor_holding_it_dies() {
    // systemd starts the hook on a failure of the service while the supervisor of the failed attempt
    // still holds the lock. If the hook gave up then and the supervisor died afterwards, nothing would
    // roll back (the service has stopped, so no agent is left to restart a supervisor).
    let world = World::new();
    world.behaves(NEW, Agent::Fails);
    let deadline = switched_unconfirmed_due_in(&world, 300);
    let start = world.clock.0.get();
    let held = hold_lock(&world);
    world.clock.at(start + 20, move || drop(held)); // the supervisor is killed
    assert_eq!(
        world.run(Intent::Rollback("the new version kept failing")),
        Ok(Ended::RolledBack)
    );
    assert!(world.clock.0.get() >= start + 20, "it did not wait");
    assert!(world.clock.0.get() < deadline, "it waited for the deadline");
    assert!(
        !world
            .systemd
            .calls
            .borrow()
            .contains(&"kill-supervisor".to_owned())
    );
    assert_eq!(world.current().as_deref(), Some(old()));
    assert_eq!(world.pending().unwrap().outcome, Outcome::RolledBack);
}

#[test]
fn the_failure_hook_leaves_the_update_to_a_supervisor_that_finishes_it() {
    let world = World::new();
    world.behaves(NEW, Agent::Fails);
    switched_unconfirmed_due_in(&world, 300);
    let start = world.clock.0.get();
    let held = hold_lock(&world);
    let state = world.state().to_owned();
    world.clock.at(start + 30, move || {
        // The supervisor rolled back by itself and removed the record before it let go of the lock.
        Record::remove(&state).unwrap();
        drop(held);
    });
    assert_eq!(
        world.run(Intent::Rollback("the new version kept failing")),
        Ok(Ended::NothingToDo)
    );
    assert!(
        !world
            .systemd
            .calls
            .borrow()
            .contains(&"kill-supervisor".to_owned())
    );
    assert_eq!(world.systemd.restarts(), 0);
}

#[test]
fn the_failure_hook_stops_a_supervisor_hung_past_its_deadline_and_rolls_back() {
    let world = World::new();
    world.behaves(NEW, Agent::Fails);
    let deadline = switched_unconfirmed_due_in(&world, 30);
    *world.systemd.other_supervisor.borrow_mut() = Some(hold_lock(&world));
    assert_eq!(
        world.run(Intent::Rollback("the new version kept failing")),
        Ok(Ended::RolledBack)
    );
    assert!(world.clock.0.get() >= deadline + OVERDUE_GRACE.as_secs());
    assert_eq!(
        world
            .systemd
            .calls
            .borrow()
            .iter()
            .filter(|c| *c == "kill-supervisor")
            .count(),
        1
    );
    assert_eq!(world.current().as_deref(), Some(old()));
    assert_eq!(world.pending().unwrap().outcome, Outcome::RolledBack);
}

#[test]
fn the_failure_hook_never_runs_alongside_a_lock_holder_it_cannot_stop() {
    // Whatever holds the lock, the hook proceeds only once it holds it itself: two supervisors never
    // act at once. If killing the supervisor unit does not free it, the hook stops and changes nothing.
    let world = World::new();
    world.behaves(NEW, Agent::Fails);
    switched_unconfirmed_due_in(&world, 30);
    let _held = hold_lock(&world);
    let error = world
        .run(Intent::Rollback("the new version kept failing"))
        .unwrap_err();
    assert!(error.contains("still held"), "{error}");
    assert_eq!(world.current().as_deref(), Some(NEW));
    assert_eq!(world.systemd.restarts(), 0);
    assert!(world.pending().is_none());
}

#[test]
fn the_failure_hook_never_touches_a_confirmed_or_unrelated_failure() {
    // Confirmed: the marker is there.
    let world = World::new();
    switched_unconfirmed(&world);
    marker(&world, world.clock.0.get())
        .write(world.state())
        .unwrap();
    assert_eq!(world.run(Intent::Rollback("x")), Ok(Ended::NothingToDo));
    assert_eq!(world.current().as_deref(), Some(NEW));

    // Not yet switched: the failure is the old version's, and no update is to blame.
    let world = World::new();
    staged(&world);
    assert_eq!(world.run(Intent::Rollback("x")), Ok(Ended::NothingToDo));
    assert_eq!(world.current().as_deref(), Some(old()));
    assert!(
        Record::read(world.state()).unwrap().is_some(),
        "the update is left alone"
    );
}

#[test]
fn a_rollback_without_the_previous_binary_stops_and_changes_nothing() {
    let world = World::new();
    world.behaves(NEW, Agent::Fails);
    switched_unconfirmed(&world);
    fs::remove_file(world.layout.binary(old())).unwrap();
    let error = world.run(Intent::Rollback("x")).unwrap_err();
    assert!(error.contains("previous version's binary"), "{error}");
    assert_eq!(world.current().as_deref(), Some(NEW));
    assert!(Record::read(world.state()).unwrap().is_some());
}

// --- Helpers ---------------------------------------------------------------------------------------

#[test]
fn the_state_backup_holds_the_records_and_not_the_updaters_own_files() {
    let world = World::new();
    fs::write(world.state().join("update.lock"), "").unwrap();
    fs::write(world.state().join(".hidden"), "x").unwrap();
    fs::create_dir_all(world.state().join("subdir")).unwrap();
    backup_state(&world.layout).unwrap();
    let mut names: Vec<_> = fs::read_dir(world.layout.backup_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["heartbeat.json", "inventory.json"]);
    fs::write(world.state().join("inventory.json"), "changed").unwrap();
    restore_state(&world.layout).unwrap();
    assert_eq!(world.inventory(), r#"{"v":"old"}"#);
}

#[test]
fn pruning_keeps_exactly_the_versions_the_links_point_to() {
    let world = World::new();
    for v in ["0.0.1", "0.0.2", NEW] {
        fs::create_dir_all(world.layout.version_dir(v)).unwrap();
    }
    crate::fsx::replace_symlink(
        &world.layout.previous(),
        &Path::new("versions").join("0.0.2"),
    )
    .unwrap();
    prune_versions(&world.layout);
    let mut names: Vec<_> = fs::read_dir(world.layout.versions_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["0.0.2".to_owned(), old().to_owned()]);
    let _ = PendingResult::read(world.state());
}
