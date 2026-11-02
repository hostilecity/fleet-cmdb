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
    let _held = FileLock::try_lock(&world.state().join(LOCK_FILE))
        .unwrap()
        .unwrap();
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

#[test]
fn after_a_reboot_the_deadline_counts_from_the_restart_and_a_late_confirmation_wins() {
    let world = World::new();
    staged(&world);
    let mut record = Record::read(world.state()).unwrap().unwrap();
    fs::create_dir_all(world.layout.version_dir(NEW)).unwrap();
    fs::copy(
        world.layout.staging(NEW).join("fleet-agent"),
        world.layout.binary(NEW),
    )
    .unwrap();
    crate::fsx::replace_symlink(&world.layout.current(), &Path::new("versions").join(NEW)).unwrap();
    // The service was restarted into the new version 60 s ago; the VM then rebooted, and the new
    // version (started by systemd at boot) confirms while the next supervisor waits.
    record.phase = Phase::Switched;
    record.restarted = true;
    record.deadline_unix = Some(world.clock.0.get() + 240);
    record.write(world.state()).unwrap();
    Marker {
        rollout_id: 5,
        version: NEW.into(),
        pid: 1,
        confirmed_at: "2026-01-01T12:00:00Z".into(),
    }
    .write(world.state())
    .unwrap();
    assert_eq!(world.run(Intent::Resume), Ok(Ended::Confirmed));
    assert_eq!(world.systemd.restarts(), 0, "it was not restarted again");
    assert_eq!(world.current().as_deref(), Some(NEW));
}

#[test]
fn after_a_reboot_an_unconfirmed_version_is_rolled_back_at_the_recorded_deadline() {
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

#[test]
fn the_failure_hook_never_touches_a_confirmed_or_unrelated_failure() {
    // Confirmed: the marker is there.
    let world = World::new();
    switched_unconfirmed(&world);
    Marker {
        rollout_id: 5,
        version: NEW.into(),
        pid: 1,
        confirmed_at: "2026-01-01T12:00:00Z".into(),
    }
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
