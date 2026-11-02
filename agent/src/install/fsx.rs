//! Filesystem steps for the installer (P1-A10): atomic writes with the final mode set before any content
//! is written, symlink swaps by rename, and checks that refuse unsafe existing paths (symlinks where a
//! real file or directory belongs, other owners, group- or world-writable directories).
//!
//! Nothing here follows a symlink it did not create, and nothing changes the mode or owner of an
//! existing path: an unsafe path is refused with a message saying how to fix it.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

// The shared helpers (atomic writes, temporary-file cleanup) live in `crate::fsx`, so the installer,
// the collectors, and the state directory use one implementation (review of #68).
pub use crate::fsx::{
    Lock, Symlinks, read_regular, remove_stale_temps, replace_symlink, write_atomic,
    write_atomic_from,
};

/// What a path holds, without following a final symlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Missing,
    File,
    Dir,
    Symlink(PathBuf),
    Other,
}

pub fn kind(path: &Path) -> io::Result<Kind> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Kind::Missing),
        Err(e) => Err(e),
        Ok(m) if m.file_type().is_symlink() => Ok(Kind::Symlink(fs::read_link(path)?)),
        Ok(m) if m.is_dir() => Ok(Kind::Dir),
        Ok(m) if m.is_file() => Ok(Kind::File),
        Ok(_) => Ok(Kind::Other),
    }
}

/// Why an existing path cannot be trusted, phrased to follow the path in a sentence.
fn untrusted(path: &Path, euid: u32, want_dir: bool) -> Option<String> {
    let metadata = match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => return Some(format!("cannot be inspected: {e}")),
        Ok(m) => m,
    };
    if metadata.file_type().is_symlink() {
        return Some("is a symlink".into());
    }
    if want_dir && !metadata.is_dir() {
        return Some("is not a directory".into());
    }
    if !want_dir && !metadata.is_file() {
        return Some("is not a regular file".into());
    }
    if metadata.uid() != euid {
        return Some(format!(
            "is owned by uid {}, not uid {euid} that the agent runs as",
            metadata.uid()
        ));
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Some(format!("has mode {mode:04o}, writable by group or others"));
    }
    None
}

/// Checks that `path`, if it exists, is a real directory owned by `euid` and not writable by group or
/// others. Returns the reason it cannot be trusted.
pub fn check_dir(path: &Path, euid: u32) -> Option<String> {
    untrusted(path, euid, true)
}

/// As [`check_dir`] for a regular file.
pub fn check_file(path: &Path, euid: u32) -> Option<String> {
    untrusted(path, euid, false)
}

/// As [`check_dir`], and also closed to group and others (the state directory, DEC-03).
pub fn check_private_dir(path: &Path, euid: u32) -> Option<String> {
    if let Some(reason) = check_dir(path, euid) {
        return Some(reason);
    }
    let mode = fs::symlink_metadata(path).ok()?.permissions().mode() & 0o7777;
    (mode & 0o077 != 0).then(|| format!("has mode {mode:04o}; it must be private (0700)"))
}

/// Creates directory `path` with exactly `mode` if it is missing (its parent must exist), then checks it
/// as [`check_dir`] does. An existing directory is never changed. Returns whether it was created.
pub fn ensure_dir(path: &Path, mode: u32, euid: u32) -> io::Result<bool> {
    let created = match DirBuilder::new().mode(mode).create(path) {
        Ok(()) => {
            // The umask may have removed bits; set exactly `mode` on the new, empty directory.
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
            true
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!("cannot create {}: {e}", path.display()),
            ));
        }
    };
    if let Some(reason) = check_dir(path, euid) {
        return Err(io::Error::other(format!("{} {reason}", path.display())));
    }
    Ok(created)
}

/// Whether two files have the same contents.
/// Files of different sizes are not read; the agent binary is a few MiB.
pub fn same_contents(a: &Path, b: &Path) -> io::Result<bool> {
    Ok(fs::metadata(a)?.len() == fs::metadata(b)?.len() && fs::read(a)? == fs::read(b)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn uid() -> u32 {
        crate::owner::effective_uid()
    }

    #[test]
    fn replace_symlink_swaps_links_and_refuses_anything_else() {
        let dir = TempDir::new();
        let link = dir.path("current");
        replace_symlink(&link, Path::new("versions/1")).unwrap();
        replace_symlink(&link, Path::new("versions/2")).unwrap();
        assert_eq!(
            kind(&link).unwrap(),
            Kind::Symlink(PathBuf::from("versions/2"))
        );
        let file = dir.write("file", "x");
        assert!(replace_symlink(&file, Path::new("versions/2")).is_err());
        assert_eq!(fs::read_to_string(&file).unwrap(), "x");
    }

    #[test]
    fn checks_refuse_symlinks_other_owners_and_open_modes() {
        let dir = TempDir::new();
        let real = dir.path("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(check_dir(&real, uid()), None);
        assert_eq!(check_dir(&dir.path("missing"), uid()), None);
        assert!(check_private_dir(&real, uid()).unwrap().contains("0755"));
        assert!(
            check_dir(&real, uid() + 1)
                .unwrap()
                .contains("owned by uid")
        );
        let link = dir.path("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(check_dir(&link, uid()).unwrap(), "is a symlink");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            check_dir(&real, uid())
                .unwrap()
                .contains("writable by group or others")
        );
        let file = dir.write("file", "");
        assert_eq!(check_dir(&file, uid()).unwrap(), "is not a directory");
        assert_eq!(check_file(&file, uid()), None);
        assert_eq!(check_file(&real, uid()).unwrap(), "is not a regular file");
    }

    #[test]
    fn ensure_dir_creates_with_the_exact_mode_and_never_changes_an_existing_one() {
        let dir = TempDir::new();
        let path = dir.path("etc");
        assert!(ensure_dir(&path, 0o700, uid()).unwrap());
        assert_eq!(mode(&path), 0o700);
        assert!(!ensure_dir(&path, 0o755, uid()).unwrap());
        assert_eq!(mode(&path), 0o700);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(ensure_dir(&path, 0o700, uid()).is_err());
        assert_eq!(mode(&path), 0o777);
    }

    #[test]
    fn same_contents_compares_bytes() {
        let dir = TempDir::new();
        let a = dir.write("a", "abc");
        let b = dir.write("b", "abc");
        let c = dir.write("c", "abd");
        assert!(same_contents(&a, &b).unwrap());
        assert!(!same_contents(&a, &c).unwrap());
        assert!(!same_contents(&a, &dir.write("d", "abcd")).unwrap());
    }
}
