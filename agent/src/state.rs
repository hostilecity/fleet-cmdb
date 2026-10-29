//! Persistent agent state under `/var/lib/fleet-agent` (FR-1.6, DEC-03).
//!
//! Holds small records such as the last boot identifier and the last reported stable facts (and, in
//! Phase 3, task records). Losing the directory must never break enrollment: the credential lives in
//! the config file, not here, and the directory is recreated at startup. P1-AGENT-CORE creates and
//! secures the directory; P1-AGENT-REPORT adds the records, written atomically, with missing or corrupt
//! state treated as empty.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Only the agent's service account (root, DEC-03) may use the state directory.
pub const STATE_DIR_MODE: u32 = 0o700;

/// Creates `dir` (and missing parents) with mode 0700 if it does not exist, then checks it is a
/// directory the agent can trust. Returns `true` if it had to be created.
///
/// An existing directory is never changed: a mistaken `state_dir` such as `/var/lib` must not have its
/// permissions rewritten (review of #65). It must be a real directory, not a symlink, owned by the
/// user the agent runs as, and closed to group and others; otherwise this fails and says what to fix.
/// The checks use a handle opened with `O_NOFOLLOW`, so a symlink swapped in cannot redirect them.
pub fn ensure_dir(dir: &Path) -> io::Result<bool> {
    ensure_dir_as(dir, crate::owner::effective_uid())
}

fn ensure_dir_as(dir: &Path, euid: u32) -> io::Result<bool> {
    // Only for the "created" log line; the checks below do not rely on it.
    let existed = fs::symlink_metadata(dir).is_ok();
    if !existed {
        DirBuilder::new()
            .recursive(true)
            .mode(STATE_DIR_MODE)
            .create(dir)?;
    }
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .map_err(|e| match e.raw_os_error() {
            // Linux reports a symlink opened with O_DIRECTORY | O_NOFOLLOW as ENOTDIR, other
            // systems as ELOOP; either way the open failed, so the lookup below only picks the
            // message.
            Some(libc::ELOOP | libc::ENOTDIR) => {
                let is_link = fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink());
                if is_link {
                    refuse(dir, "is a symlink; point state_dir at the real directory")
                } else {
                    refuse(dir, "exists but is not a directory")
                }
            }
            _ => e,
        })?;
    let metadata = handle.metadata()?;
    if !crate::owner::trusted_owner(metadata.uid(), euid) {
        return Err(refuse(
            dir,
            &format!(
                "is owned by uid {}, not uid {euid} that the agent runs as; use a directory of its own",
                metadata.uid()
            ),
        ));
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(refuse(
            dir,
            &format!(
                "has mode {mode:04o}; the agent's state must be private (0700). If this directory is the agent's own, fix it with `chmod 700 {}`; never point state_dir at a shared directory",
                dir.display()
            ),
        ));
    }
    Ok(!existed)
}

fn refuse(dir: &Path, why: &str) -> io::Error {
    io::Error::other(format!("state directory {} {why}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use std::os::unix::fs::MetadataExt;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn creates_missing_directory_with_mode_0700() {
        let tmp = TempDir::new();
        let dir = tmp.path("var/lib/fleet-agent");
        assert!(ensure_dir(&dir).unwrap());
        assert_eq!(mode(&dir), 0o700);
        // Idempotent.
        assert!(!ensure_dir(&dir).unwrap());
    }

    #[test]
    fn recreates_a_lost_directory() {
        let tmp = TempDir::new();
        let dir = tmp.path("state");
        ensure_dir(&dir).unwrap();
        fs::remove_dir_all(&dir).unwrap();
        assert!(ensure_dir(&dir).unwrap());
        assert!(dir.is_dir());
    }

    #[test]
    fn refuses_an_open_directory_and_leaves_it_alone() {
        // A state_dir such as /var/lib must never have its permissions rewritten (review of #65).
        let tmp = TempDir::new();
        let dir = tmp.path("shared");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let error = ensure_dir(&dir).unwrap_err().to_string();
        assert!(error.contains("has mode 0755"), "{error}");
        assert!(error.contains("chmod 700"), "{error}");
        assert_eq!(mode(&dir), 0o755);
    }

    #[test]
    fn accepts_an_existing_private_directory_without_changing_it() {
        let tmp = TempDir::new();
        let dir = tmp.path("state");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!ensure_dir(&dir).unwrap());
        assert_eq!(mode(&dir), 0o700);
    }

    #[test]
    fn refuses_a_symlink_even_to_a_private_directory() {
        let tmp = TempDir::new();
        let real = tmp.path("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let link = tmp.path("state");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let error = ensure_dir(&link).unwrap_err().to_string();
        assert!(error.contains("is a symlink"), "{error}");
    }

    #[test]
    fn refuses_a_directory_owned_by_another_user() {
        let tmp = TempDir::new();
        let dir = tmp.path("state");
        ensure_dir(&dir).unwrap();
        let owner = fs::metadata(&dir).unwrap().uid();
        let error = ensure_dir_as(&dir, owner.wrapping_add(1))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("is owned by uid {owner}")),
            "{error}"
        );
    }

    #[test]
    fn refuses_a_file_in_the_way() {
        let tmp = TempDir::new();
        let file = tmp.write("state", "");
        let error = ensure_dir(&file).unwrap_err();
        assert!(error.to_string().contains("not a directory"));
    }
}
