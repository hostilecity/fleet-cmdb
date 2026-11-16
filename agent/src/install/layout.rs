//! Step 2 of `install`: the side-by-side binary layout and the systemd unit (P1-A10; layout from
//! P1-PACKAGING and ADR 0018).
//!
//! ```text
//! /usr/lib/fleet-agent/versions/<version>/fleet-agent    the binary, mode 0755
//! /usr/lib/fleet-agent/current  -> versions/<version>      this version
//! /usr/lib/fleet-agent/previous -> versions/<older>        the version replaced by the last upgrade
//! /usr/bin/fleet-agent -> ../lib/fleet-agent/current/fleet-agent
//! /etc/systemd/system/fleet-agent.service                  the unit built into the binary
//! ```
//!
//! Links are swapped by renaming a new link over the old one, so `current` always points at a complete
//! binary. Two versions are kept (ADR 0018); older version directories are removed.

use std::fs::{self, File};
use std::path::{Path, PathBuf};

use crate::AGENT_VERSION;

use super::fsx::{self, Kind, Lock};
use super::systemd::{RECOVERY_UNIT, ROLLBACK_UNIT, UNIT};
use super::ui::Ui;
use super::{Failure, Host, InstallError};

/// What step 2 did.
pub struct Installed {
    /// The binary, a link, or the unit changed, so the service must be restarted.
    pub changed: bool,
}

fn io_failed(what: &str, path: &Path, e: impl std::fmt::Display) -> InstallError {
    InstallError::failed(format!("cannot {what} {}: {e}", path.display()))
}

/// Takes the installer lock on `/usr/lib/fleet-agent` (creating the directory), so two installs or an
/// install and an uninstall cannot interleave.
pub fn lock(host: &Host) -> Result<Lock, InstallError> {
    let dir = host.paths.lib_dir();
    fsx::ensure_dir(&dir, 0o755, host.owner_uid)
        .map_err(|e| InstallError::failed(e.to_string()))?;
    match Lock::dir(&dir) {
        Ok(Some(lock)) => Ok(lock),
        Ok(None) => Err(InstallError::new(
            Failure::Failed,
            "another fleet-agent install or uninstall is running on this VM",
            "Wait for it to finish, then run the command again if it is still needed.",
        )),
        Err(e) => Err(io_failed("lock", &dir, e)),
    }
}

/// Holds the agent's update lock for as long as an install or uninstall runs, and refuses while an
/// agent update is in progress (P1-AGENT-UPDATE): changing `/usr/lib/fleet-agent` under a supervisor
/// could remove the version its rollback needs. Covers the default state directory and the one the
/// existing config names.
pub fn hold_updates(host: &Host) -> Result<Vec<crate::fsx::Lock>, InstallError> {
    let mut dirs = vec![host.paths.state_dir()];
    if let Ok(config) = crate::config::Config::load_as(&host.paths.config(), host.owner_uid) {
        let other = host.paths.state_dir_of(&config);
        if !dirs.contains(&other) {
            dirs.push(other);
        }
    }
    let mut held = Vec::new();
    for dir in dirs {
        match crate::update::hold_for_install(&dir) {
            Ok(Some(lock)) => held.push(lock),
            Ok(None) => {}
            Err(why) => {
                return Err(InstallError::new(
                    Failure::Failed,
                    why,
                    "Wait for the update to finish (it rolls back by itself if the new version does not confirm), then run the command again. `journalctl -u fleet-agent-update -u fleet-agent` shows how it is going.",
                ));
            }
        }
    }
    Ok(held)
}

pub fn install(host: &Host, ui: &mut Ui) -> Result<Installed, InstallError> {
    let paths = &host.paths;
    let uid = host.owner_uid;
    let version_rel = PathBuf::from("versions").join(AGENT_VERSION);
    let version_dir = paths.lib_dir().join(&version_rel);
    let binary = version_dir.join("fleet-agent");
    let mut changed = false;

    for dir in [paths.versions_dir(), version_dir.clone()] {
        fsx::ensure_dir(&dir, 0o755, uid).map_err(|e| InstallError::failed(e.to_string()))?;
    }
    fsx::remove_stale_temps(&version_dir, "fleet-agent")
        .and_then(|_| fsx::remove_stale_temps(&paths.lib_dir(), ""))
        .and_then(|_| match paths.bin_link().parent() {
            Some(bin) => fsx::remove_stale_temps(bin, "fleet-agent"),
            None => Ok(0),
        })
        .map_err(|e| io_failed("clean up", &paths.lib_dir(), e))?;

    // The binary: copied from the running executable unless an identical copy is already in place.
    let up_to_date = match fsx::kind(&binary).map_err(|e| io_failed("inspect", &binary, e))? {
        Kind::Missing => false,
        Kind::File => {
            if let Some(reason) = fsx::check_file(&binary, uid) {
                return Err(io_failed("use", &binary, reason));
            }
            fsx::same_contents(&host.exe, &binary).map_err(|e| io_failed("compare", &binary, e))?
        }
        _ => return Err(io_failed("use", &binary, "it is not a regular file")),
    };
    if up_to_date {
        ui.detail(&format!("{} is already in place.", binary.display()));
    } else {
        let mut source = File::open(&host.exe)
            .map_err(|e| io_failed("read the running binary", &host.exe, e))?;
        fsx::write_atomic_from(&binary, &mut source, 0o755)
            .map_err(|e| io_failed("write", &binary, e))?;
        ui.detail(&format!("Installed {}", binary.display()));
        changed = true;
    }

    // current -> this version; the version it replaces becomes previous.
    let current =
        fsx::kind(&paths.current()).map_err(|e| io_failed("inspect", &paths.current(), e))?;
    if current != Kind::Symlink(version_rel.clone()) {
        if let Kind::Symlink(old) = &current {
            fsx::replace_symlink(&paths.previous(), old)
                .map_err(|e| io_failed("update", &paths.previous(), e))?;
            ui.detail(&format!(
                "Previous version {} kept for rollback.",
                old.file_name()
                    .map(|n| n.to_string_lossy())
                    .unwrap_or_default()
            ));
        }
        fsx::replace_symlink(&paths.current(), &version_rel)
            .map_err(|e| io_failed("update", &paths.current(), e))?;
        ui.detail(&format!(
            "{} now points to version {AGENT_VERSION}.",
            paths.current().display()
        ));
        changed = true;
    }

    let bin_target = Path::new("../lib/fleet-agent/current/fleet-agent");
    if fsx::kind(&paths.bin_link()).map_err(|e| io_failed("inspect", &paths.bin_link(), e))?
        != Kind::Symlink(bin_target.to_owned())
    {
        fsx::replace_symlink(&paths.bin_link(), bin_target)
            .map_err(|e| io_failed("update", &paths.bin_link(), e))?;
        ui.detail(&format!(
            "Linked {} to the current version.",
            paths.bin_link().display()
        ));
    }

    prune_versions(host, ui)?;

    if write_units(host, ui)? {
        changed = true;
    }
    Ok(Installed { changed })
}

/// The units built into this binary: the service, and the rollback and recovery units its `OnFailure=`
/// starts (ADR 0018, ADR 0030). Each is written only if it differs, then `daemon-reload` once if any was.
/// Returns whether any was written.
pub fn write_units(host: &Host, ui: &mut Ui) -> Result<bool, InstallError> {
    let paths = &host.paths;
    let mut wrote_unit = false;
    for (unit, text) in [
        (paths.unit(), UNIT),
        (paths.rollback_unit(), ROLLBACK_UNIT),
        (paths.recovery_unit(), RECOVERY_UNIT),
    ] {
        let same = fs::read(&unit).is_ok_and(|bytes| bytes == text.as_bytes());
        if same {
            ui.detail(&format!("{} is up to date.", unit.display()));
            continue;
        }
        let name = unit
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        fsx::remove_stale_temps(&paths.unit_dir(), &name)
            .map_err(|e| io_failed("clean up", &paths.unit_dir(), e))?;
        fsx::write_atomic(&unit, text.as_bytes(), 0o644)
            .map_err(|e| io_failed("write", &unit, e))?;
        ui.detail(&format!("Wrote {}", unit.display()));
        wrote_unit = true;
    }
    if wrote_unit {
        host.systemd.daemon_reload().map_err(|e| {
            InstallError::failed(format!(
                "systemctl daemon-reload failed after writing the units in {}: {e}",
                paths.unit_dir().display()
            ))
        })?;
    }
    Ok(wrote_unit)
}

/// Everything `install --refresh-units` checks before it writes a unit (#232). Nothing is changed when one
/// fails.
///
/// - `current` is this version and its binary is this one: the units name `current/fleet-agent` and the
///   arguments of this version (an older binary would refuse `run --recovery`, ADR 0030).
/// - No update is in progress, other than a confirmed one of this version: the supervisor runs the refresh
///   after the confirmation and before it removes the record. An unconfirmed version may still be rolled
///   back, and its units would then run the older binary.
/// - Each unit file is safe to replace (owned by root, not writable by others, not a link), and carries
///   the installer's marker. The rollback and recovery units may be missing (an install from before they
///   existed), and are then written. The service unit must be there and be the installer's: without it
///   this is not an installed agent, and a unit in `/etc/systemd/system` would hide a packaged one. A unit
///   without the marker is someone's local copy: it is left alone, and so are the others.
pub fn check_refresh(host: &Host) -> Result<(), InstallError> {
    let paths = &host.paths;
    let refuse = |what: String, next: &str| InstallError::new(Failure::Preflight, what, next);
    let version_rel = PathBuf::from("versions").join(AGENT_VERSION);
    let current =
        fsx::kind(&paths.current()).map_err(|e| io_failed("inspect", &paths.current(), e))?;
    let this_version = current == Kind::Symlink(version_rel.clone())
        && fsx::same_contents(
            &host.exe,
            &paths.lib_dir().join(&version_rel).join("fleet-agent"),
        )
        .unwrap_or(false);
    if !this_version {
        return Err(refuse(
            format!(
                "{} is not this fleet-agent {AGENT_VERSION}; only the version that runs may write its units",
                paths.current().display()
            ),
            "Run the command with the installed binary: `sudo /usr/lib/fleet-agent/current/fleet-agent install --refresh-units`, or upgrade with `sudo fleet-agent install`.",
        ));
    }
    let mut dirs = vec![paths.state_dir()];
    if let Ok(config) = crate::config::Config::load_as(&paths.config(), host.owner_uid) {
        let other = paths.state_dir_of(&config);
        if !dirs.contains(&other) {
            dirs.push(other);
        }
    }
    for dir in dirs {
        crate::update::check_refresh_units(&dir).map_err(|why| {
            InstallError::new(
                Failure::Failed,
                why,
                "Wait for the update to finish; a confirmed update refreshes the units itself.",
            )
        })?;
    }
    if let Some(reason) = fsx::check_dir(&paths.unit_dir(), host.owner_uid) {
        return Err(refuse(
            format!("{} {reason}", paths.unit_dir().display()),
            "The unit directory must be owned by root and not writable by others.",
        ));
    }
    for (unit, required) in [
        (paths.unit(), true),
        (paths.rollback_unit(), false),
        (paths.recovery_unit(), false),
    ] {
        let local_copy = "Move it away (keep local changes in a drop-in made with `systemctl edit`), then run the command again.";
        match fsx::kind(&unit).map_err(|e| io_failed("inspect", &unit, e))? {
            Kind::Missing if !required => continue,
            Kind::Missing => {
                return Err(refuse(
                    format!(
                        "{} is missing; this VM has no installed agent to refresh",
                        unit.display()
                    ),
                    "Install the agent with `sudo fleet-agent install`.",
                ));
            }
            Kind::File => {}
            _ => {
                return Err(refuse(
                    format!("{} is not a regular file", unit.display()),
                    local_copy,
                ));
            }
        }
        if let Some(reason) = fsx::check_file(&unit, host.owner_uid) {
            return Err(refuse(format!("{} {reason}", unit.display()), local_copy));
        }
        let marked = fs::read(&unit)
            .map_err(|e| io_failed("read", &unit, e))?
            .starts_with(super::systemd::UNIT_MARKER.as_bytes());
        if !marked {
            return Err(refuse(
                format!(
                    "{} was not written by fleet-agent install; no unit was changed",
                    unit.display()
                ),
                local_copy,
            ));
        }
    }
    Ok(())
}

/// Keeps the versions `current` and `previous` point to and removes the others (ADR 0018 retention).
fn prune_versions(host: &Host, ui: &mut Ui) -> Result<(), InstallError> {
    let paths = &host.paths;
    let keep: Vec<PathBuf> = [paths.current(), paths.previous()]
        .iter()
        .filter_map(|link| match fsx::kind(link) {
            Ok(Kind::Symlink(target)) => target.file_name().map(PathBuf::from),
            _ => None,
        })
        .collect();
    let dir = paths.versions_dir();
    let entries = fs::read_dir(&dir).map_err(|e| io_failed("list", &dir, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| io_failed("list", &dir, e))?;
        let name = PathBuf::from(entry.file_name());
        if keep.contains(&name) {
            continue;
        }
        let path = entry.path();
        // remove_dir_all never follows symlinks inside the tree; the entry itself must be a real
        // directory owned by the installer's user.
        if fsx::check_dir(&path, host.owner_uid).is_none() && path.is_dir() {
            fs::remove_dir_all(&path).map_err(|e| io_failed("remove the old version", &path, e))?;
            ui.detail(&format!("Removed old version {}.", name.display()));
        }
    }
    Ok(())
}
