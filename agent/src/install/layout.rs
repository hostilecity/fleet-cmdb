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

use super::fsx::{self, DirLock, Kind};
use super::systemd::UNIT;
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
pub fn lock(host: &Host) -> Result<DirLock, InstallError> {
    let dir = host.paths.lib_dir();
    fsx::ensure_dir(&dir, 0o755, host.owner_uid)
        .map_err(|e| InstallError::failed(e.to_string()))?;
    match DirLock::try_lock(&dir) {
        Ok(Some(lock)) => Ok(lock),
        Ok(None) => Err(InstallError::new(
            Failure::Failed,
            "another fleet-agent install or uninstall is running on this VM",
            "Wait for it to finish, then run the command again if it is still needed.",
        )),
        Err(e) => Err(io_failed("lock", &dir, e)),
    }
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

    // The unit, built into this binary.
    let unit = paths.unit();
    let same = fs::read(&unit).is_ok_and(|bytes| bytes == UNIT.as_bytes());
    if same {
        ui.detail(&format!("{} is up to date.", unit.display()));
    } else {
        fsx::remove_stale_temps(&paths.unit_dir(), super::systemd::UNIT_NAME)
            .map_err(|e| io_failed("clean up", &paths.unit_dir(), e))?;
        fsx::write_atomic(&unit, UNIT.as_bytes(), 0o644)
            .map_err(|e| io_failed("write", &unit, e))?;
        host.systemd.daemon_reload().map_err(|e| {
            InstallError::failed(format!(
                "systemctl daemon-reload failed after writing {}: {e}",
                unit.display()
            ))
        })?;
        ui.detail(&format!("Wrote {}", unit.display()));
        changed = true;
    }
    Ok(Installed { changed })
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
