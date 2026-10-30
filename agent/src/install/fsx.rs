//! Filesystem steps for the installer (P1-A10): atomic writes with the final mode set before any content
//! is written, symlink swaps by rename, and checks that refuse unsafe existing paths (symlinks where a
//! real file or directory belongs, other owners, group- or world-writable directories).
//!
//! Nothing here follows a symlink it did not create, and nothing changes the mode or owner of an
//! existing path: an unsafe path is refused with a message saying how to fix it.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

// The shared helpers (atomic writes, temporary-file cleanup) live in `crate::fsx`, so the installer,
// the collectors, and the state directory use one implementation (review of #68).
use crate::fsx::temp_path;
pub use crate::fsx::{remove_stale_temps, sync_dir, write_atomic, write_atomic_from};

/// Points the symlink `link` at `target`, replacing an existing symlink atomically (a new link is made
/// under a temporary name and renamed over the old one). Refuses to replace anything but a symlink.
pub fn replace_symlink(link: &Path, target: &Path) -> io::Result<()> {
    match fs::symlink_metadata(link) {
        Ok(m) if !m.file_type().is_symlink() => {
            return Err(io::Error::other(format!(
                "{} exists and is not a symlink",
                link.display()
            )));
        }
        _ => {}
    }
    let temp = temp_path(link);
    std::os::unix::fs::symlink(target, &temp)?;
    let result =
        fs::rename(&temp, link).and_then(|()| sync_dir(link.parent().unwrap_or(Path::new("/"))));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

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
pub fn same_contents(a: &Path, b: &Path) -> io::Result<bool> {
    let (mut fa, mut fb) = (File::open(a)?, File::open(b)?);
    if fa.metadata()?.len() != fb.metadata()?.len() {
        return Ok(false);
    }
    let (mut ba, mut bb) = (vec![0u8; 64 * 1024], vec![0u8; 64 * 1024]);
    loop {
        let n = read_full(&mut fa, &mut ba)?;
        let m = read_full(&mut fb, &mut bb)?;
        if n != m || ba[..n] != bb[..m] {
            return Ok(false);
        }
        if n == 0 {
            return Ok(true);
        }
    }
}

fn read_full(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// An exclusive, non-blocking `flock` on a directory, so two installers cannot run at once. Released
/// when dropped (or when the process exits).
pub struct DirLock(#[allow(dead_code)] File);

impl DirLock {
    /// `Ok(None)` when another process holds the lock.
    pub fn try_lock(dir: &Path) -> io::Result<Option<Self>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir)?;
        // SAFETY: `file` is an open descriptor for the duration of the call; flock has no other inputs.
        let rc = unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&file),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        };
        if rc == 0 {
            return Ok(Some(Self(file)));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            Ok(None)
        } else {
            Err(error)
        }
    }
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

    #[test]
    fn a_second_lock_is_refused_until_the_first_is_released() {
        let dir = TempDir::new();
        let first = DirLock::try_lock(dir.root()).unwrap();
        assert!(first.is_some());
        assert!(DirLock::try_lock(dir.root()).unwrap().is_none());
        drop(first);
        assert!(DirLock::try_lock(dir.root()).unwrap().is_some());
    }
}
