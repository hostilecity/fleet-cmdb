//! `fleet-agent uninstall` (P1-A10): removes what `install` created, and nothing else.
//!
//! In order: stop and disable the service, remove the unit (only if the installer wrote it),
//! `/usr/bin/fleet-agent` (only if it is the installer's link), `/usr/lib/fleet-agent`, and, unless
//! `--keep-state`, the config, the copied CA certificate, `/etc/fleet-agent` if nothing else is in it,
//! and the default state directory. A state directory configured elsewhere, or files someone else put
//! in `/etc/fleet-agent`, are listed and left alone. The host record on the server is not touched.
//! Running it again when nothing is installed succeeds and says so.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::config::Config;

use super::fsx::{self, DirLock, Kind};
use super::systemd::{UNIT_MARKER, UNIT_NAME};
use super::ui::Ui;
use super::{Failure, Host, InstallError, UninstallOptions};

pub fn uninstall(host: &Host, options: &UninstallOptions, ui: &mut Ui) -> Result<(), InstallError> {
    if !host.is_root {
        return Err(InstallError::new(
            Failure::Preflight,
            "uninstall must run as root: it removes a system service and root-only files",
            format!("Run it again with sudo: {}", host.sudo_command),
        ));
    }
    ui.title(&format!("fleet-agent {}: uninstall", crate::AGENT_VERSION));
    let paths = &host.paths;
    let uid = host.owner_uid;
    let mut removed: Vec<String> = Vec::new();
    let mut kept: Vec<String> = Vec::new();

    let _lock = match DirLock::try_lock(&paths.lib_dir()) {
        Ok(None) => {
            return Err(InstallError::new(
                Failure::Failed,
                "a fleet-agent install or uninstall is running on this VM",
                "Wait for it to finish, then run the command again.",
            ));
        }
        Ok(Some(lock)) => Some(lock),
        Err(_) => None, // no lib directory: nothing installed there
    };
    // Read before anything is removed: a custom state directory is named only in the config.
    let config = Config::load_as(&paths.config(), uid).ok();

    // The service.
    let unit = paths.unit();
    let unit_is_ours = fs::read_to_string(&unit).is_ok_and(|t| t.starts_with(UNIT_MARKER))
        && fsx::check_file(&unit, uid).is_none();
    if host.systemd.unavailable().is_none() {
        let known = unit_is_ours || host.systemd.state() != "inactive" || host.systemd.is_enabled();
        if known {
            if let Err(e) = host.systemd.systemctl(&["disable", "--now", UNIT_NAME]) {
                if unit_is_ours {
                    return Err(failed(format!("cannot stop and disable {UNIT_NAME}: {e}")));
                }
            } else {
                ui.detail(&format!("Stopped and disabled {UNIT_NAME}."));
            }
        }
    }
    if unit_is_ours {
        remove_file(&unit, &mut removed, ui)?;
        if host.systemd.unavailable().is_none() {
            let _ = host.systemd.daemon_reload();
            let _ = host.systemd.systemctl(&["reset-failed", UNIT_NAME]);
        }
    } else if unit.exists() {
        keep(
            &mut kept,
            ui,
            format!("{} (not written by the installer)", unit.display()),
        );
    }

    // The binaries.
    let bin = paths.bin_link();
    match fsx::kind(&bin) {
        Ok(Kind::Symlink(target)) if target.to_string_lossy().contains("fleet-agent/current") => {
            remove_file(&bin, &mut removed, ui)?;
        }
        Ok(Kind::Missing) => {}
        _ => keep(
            &mut kept,
            ui,
            format!("{} (not the installer's link)", bin.display()),
        ),
    }
    remove_tree(&paths.lib_dir(), uid, &mut removed, &mut kept, ui)?;

    // The config and the state.
    if options.keep_state {
        for path in [paths.etc_dir(), paths.state_dir()] {
            if path.exists() {
                keep(&mut kept, ui, format!("{} (--keep-state)", path.display()));
            }
        }
    } else {
        let etc = paths.etc_dir();
        if fsx::check_dir(&etc, uid).is_none() && etc.is_dir() {
            for name in ["config.toml", "ca.pem"] {
                let path = etc.join(name);
                if path.exists() || fs::symlink_metadata(&path).is_ok() {
                    remove_file(&path, &mut removed, ui)?;
                }
            }
            for name in ["config.toml", "ca.pem"] {
                fsx::remove_stale_temps(&etc, name)
                    .map_err(|e| failed(format!("cannot clean up {}: {e}", etc.display())))?;
            }
            match fs::remove_dir(&etc) {
                Ok(()) => {
                    ui.detail(&format!("Removed {}", etc.display()));
                    removed.push(etc.display().to_string());
                }
                Err(_) => {
                    let others: Vec<String> = fs::read_dir(&etc)
                        .map(|entries| {
                            entries
                                .filter_map(|e| e.ok())
                                .map(|e| e.file_name().to_string_lossy().into_owned())
                                .collect()
                        })
                        .unwrap_or_default();
                    keep(
                        &mut kept,
                        ui,
                        format!(
                            "{} (also holds files the installer did not create: {})",
                            etc.display(),
                            others.join(", ")
                        ),
                    );
                }
            }
        } else if fs::symlink_metadata(&etc).is_ok() {
            keep(
                &mut kept,
                ui,
                format!("{} (not a directory the installer made)", etc.display()),
            );
        }

        remove_tree(&paths.state_dir(), uid, &mut removed, &mut kept, ui)?;
        if let Some(config) = &config {
            let custom = paths.state_dir_of(config);
            if custom != paths.state_dir() && custom.exists() {
                keep(
                    &mut kept,
                    ui,
                    format!(
                        "{} (state_dir set in the config; remove it yourself if it is the agent's)",
                        custom.display()
                    ),
                );
            }
        }
    }

    let headline = if removed.is_empty() {
        "Nothing to remove: fleet-agent is not installed on this VM.".to_owned()
    } else {
        "Done. fleet-agent is uninstalled. The host record on the server is unchanged; retire the host in the dashboard if this VM is gone.".to_owned()
    };
    let rows: Vec<(&str, String)> = if removed.is_empty() {
        Vec::new()
    } else {
        vec![("Removed", removed.join(", "))]
    };
    ui.summary(
        &headline,
        "uninstalled",
        &rows,
        json!({"removed": removed, "kept": kept}),
    );
    Ok(())
}

fn failed(what: String) -> InstallError {
    InstallError::new(
        Failure::Failed,
        what,
        "Fix the cause, then run `sudo fleet-agent uninstall` again; it continues from where it stopped.",
    )
}

fn keep(kept: &mut Vec<String>, ui: &mut Ui, text: String) {
    ui.detail(&format!("Left {text}."));
    kept.push(text);
}

fn remove_file(path: &Path, removed: &mut Vec<String>, ui: &mut Ui) -> Result<(), InstallError> {
    fs::remove_file(path).map_err(|e| failed(format!("cannot remove {}: {e}", path.display())))?;
    ui.detail(&format!("Removed {}", path.display()));
    removed.push(path.display().to_string());
    Ok(())
}

/// Removes a directory tree the installer owns: a real directory (not a symlink) owned by `uid`.
/// `remove_dir_all` does not follow symlinks inside the tree.
fn remove_tree(
    path: &PathBuf,
    uid: u32,
    removed: &mut Vec<String>,
    kept: &mut Vec<String>,
    ui: &mut Ui,
) -> Result<(), InstallError> {
    match fsx::kind(path) {
        Ok(Kind::Missing) => Ok(()),
        Ok(Kind::Dir) => {
            let metadata = fs::symlink_metadata(path)
                .map_err(|e| failed(format!("cannot inspect {}: {e}", path.display())))?;
            if std::os::unix::fs::MetadataExt::uid(&metadata) != uid {
                keep(
                    kept,
                    ui,
                    format!("{} (owned by another user)", path.display()),
                );
                return Ok(());
            }
            fs::remove_dir_all(path)
                .map_err(|e| failed(format!("cannot remove {}: {e}", path.display())))?;
            ui.detail(&format!("Removed {}", path.display()));
            removed.push(path.display().to_string());
            Ok(())
        }
        _ => {
            keep(
                kept,
                ui,
                format!("{} (not a directory the installer made)", path.display()),
            );
            Ok(())
        }
    }
}
