//! Persistent agent state under `/var/lib/fleet-agent` (FR-1.6, DEC-03).
//!
//! Holds small records such as the last boot identifier and the last reported stable facts (and, in
//! Phase 3, task records). Losing the directory must never break enrollment: the credential lives in
//! the config file, not here, and the directory is recreated at startup. P1-AGENT-CORE creates and
//! secures the directory; P1-AGENT-REPORT adds the records, written atomically, with missing or corrupt
//! state treated as empty.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;

/// Only the agent's service account (root, DEC-03) may use the state directory.
pub const STATE_DIR_MODE: u32 = 0o700;

/// Creates `dir` (and missing parents) if needed and makes sure only its owner can use it. Returns
/// `true` if the directory had to be created or its permissions tightened.
pub fn ensure_dir(dir: &Path) -> io::Result<bool> {
    let mut changed = false;
    if !dir.exists() {
        DirBuilder::new()
            .recursive(true)
            .mode(STATE_DIR_MODE)
            .create(dir)?;
        changed = true;
    }
    let metadata = fs::metadata(dir)?;
    if !metadata.is_dir() {
        return Err(io::Error::other(format!(
            "state directory {} exists but is not a directory",
            dir.display()
        )));
    }
    if metadata.permissions().mode() & 0o7777 != STATE_DIR_MODE {
        fs::set_permissions(dir, fs::Permissions::from_mode(STATE_DIR_MODE))?;
        changed = true;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

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
    fn tightens_loose_permissions() {
        let tmp = TempDir::new();
        let dir = tmp.path("state");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ensure_dir(&dir).unwrap());
        assert_eq!(mode(&dir), 0o700);
    }

    #[test]
    fn refuses_a_file_in_the_way() {
        let tmp = TempDir::new();
        let file = tmp.write("state", "");
        let error = ensure_dir(&file).unwrap_err();
        assert!(error.to_string().contains("not a directory"));
    }
}
