//! Filesystem helpers shared by the collectors, the state directory, and (P1-AGENT-INSTALL) the
//! installer: one implementation of each durability- or safety-critical step, so they cannot drift
//! apart (review of #68).
//!
//! - [`read_regular`]: read a regular file of bounded size, never waiting on a FIFO or device.
//! - [`write_atomic`]: replace a file so a crash leaves the old contents or the new, never a mix.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// Marks temporary files, so a later run can remove any left by an interrupted one
/// ([`remove_stale_temps`]).
pub const TEMP_MARKER: &str = ".fleet-agent-tmp-";

/// Whether [`read_regular`] follows a symlink at the final path component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symlinks {
    /// Follow it (system files such as `/etc/os-release` are symlinks on Debian).
    Follow,
    /// Refuse it (the agent's own files, where a symlink can only be planted).
    Refuse,
}

/// Reads the regular file at `path`, of at most `max_bytes`.
///
/// Anything but a regular file is refused before it is read. The open itself never waits:
/// `O_NONBLOCK` stops a FIFO with no writer from blocking, and `O_NOCTTY` stops a terminal device from
/// becoming the controlling terminal of the agent, which runs as root.
pub fn read_regular(path: &Path, max_bytes: u64, symlinks: Symlinks) -> io::Result<Vec<u8>> {
    let mut flags = libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC;
    if symlinks == Symlinks::Refuse {
        flags |= libc::O_NOFOLLOW;
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::other(format!("larger than {max_bytes} bytes")));
    }
    Ok(bytes)
}

/// A temporary name next to `path`, unique within this process and across processes.
pub(crate) fn temp_path(path: &Path) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!(
        ".{name}{TEMP_MARKER}{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ))
}

/// Flushes a directory entry change (a rename or unlink) to disk.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Writes `contents` to `path` atomically with exactly `mode`.
///
/// The data goes to a new temporary file in the same directory, created with `O_EXCL | O_NOFOLLOW` and
/// `mode`, and set to exactly `mode` on the open handle before anything is written (the umask can only
/// remove bits, never add them, so the file is never more open than `mode`). It is flushed, renamed over
/// `path`, and the directory is flushed. A reader sees the old file or the new one, never part of one,
/// and a failure removes the temporary file. Renaming over a symlink replaces the link, not its target.
pub fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    write_atomic_from(path, &mut &contents[..], mode)
}

/// As [`write_atomic`], copying from `source`.
pub fn write_atomic_from(path: &Path, source: &mut dyn Read, mode: u32) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("/"));
    let temp = temp_path(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)?;
    let result = (|| {
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        io::copy(source, &mut file)?;
        file.flush()?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        sync_dir(dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Removes temporary files left in `dir` by an interrupted run (names containing [`TEMP_MARKER`] and
/// starting with `.{prefix}`). Returns how many were removed. A missing directory is not an error.
pub fn remove_stale_temps(dir: &Path, prefix: &str) -> io::Result<usize> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let start = format!(".{prefix}");
    let mut removed = 0;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&start) && name.contains(TEMP_MARKER) && !entry.file_type()?.is_dir() {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    if removed > 0 {
        sync_dir(dir)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;
    use std::os::unix::fs::MetadataExt;

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn write_atomic_sets_the_exact_mode_and_leaves_no_temporary_file() {
        let tmp = TempDir::new();
        let path = tmp.path("f");
        write_atomic(&path, b"one", 0o600).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        // Replacing a more open file gives the requested mode, not the old one.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic(&path, b"two", 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        assert_eq!(names(tmp.root()), ["f"]);
    }

    #[test]
    fn write_atomic_replaces_a_symlink_without_writing_through_it() {
        let tmp = TempDir::new();
        let target = tmp.write("target", "untouched");
        let link = tmp.path("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        write_atomic(&link, b"new", 0o600).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
        assert!(
            !fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&link).unwrap(), b"new");
    }

    #[test]
    fn a_failed_write_leaves_the_old_file_and_no_temporary_file() {
        let tmp = TempDir::new();
        let path = tmp.write("f", "old");
        let mut failing = io::repeat(b'x').take(10).chain(FailingReader);
        assert!(write_atomic_from(&path, &mut failing, 0o600).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "old");
        assert_eq!(names(tmp.root()), ["f"]);
    }

    #[test]
    fn a_failed_rename_leaves_what_was_there_and_no_temporary_file() {
        // The destination is a directory, so the rename fails after the data was written and synced.
        let tmp = TempDir::new();
        let path = tmp.path("config.toml");
        fs::create_dir(&path).unwrap();
        assert!(write_atomic(&path, b"secret", 0o600).is_err());
        assert!(path.is_dir());
        assert_eq!(names(tmp.root()), ["config.toml"]);
        // Other modes are exact too (the installer writes executables).
        write_atomic(&tmp.path("tool"), b"#!", 0o755).unwrap();
        assert_eq!(
            fs::metadata(tmp.path("tool")).unwrap().mode() & 0o7777,
            0o755
        );
    }

    struct FailingReader;
    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("disk full"))
        }
    }

    #[test]
    fn stale_temporary_files_are_removed_and_nothing_else() {
        let tmp = TempDir::new();
        let dir = tmp.root();
        fs::write(dir.join(format!(".r.json{TEMP_MARKER}1-0")), "stale").unwrap();
        let target = tmp.write("target", "untouched");
        std::os::unix::fs::symlink(&target, dir.join(format!(".r.json{TEMP_MARKER}2-0"))).unwrap();
        fs::write(dir.join("r.json"), "keep").unwrap();
        fs::write(dir.join(format!(".other{TEMP_MARKER}1-0")), "other prefix").unwrap();
        assert_eq!(remove_stale_temps(dir, "r.json").unwrap(), 2);
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
        assert_eq!(
            names(dir),
            [
                format!(".other{TEMP_MARKER}1-0"),
                "r.json".into(),
                "target".into()
            ]
        );
        assert_eq!(
            remove_stale_temps(&dir.join("missing"), "r.json").unwrap(),
            0
        );
    }

    #[test]
    fn read_regular_follows_or_refuses_symlinks_as_asked() {
        let tmp = TempDir::new();
        let target = tmp.write("target", "data");
        let link = tmp.path("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(read_regular(&link, 64, Symlinks::Follow).unwrap(), b"data");
        assert!(read_regular(&link, 64, Symlinks::Refuse).is_err());
        assert_eq!(
            read_regular(&target, 64, Symlinks::Refuse).unwrap(),
            b"data"
        );
    }

    #[test]
    fn read_regular_refuses_directories_devices_and_oversized_files() {
        let tmp = TempDir::new();
        let error = read_regular(tmp.root(), 64, Symlinks::Follow).unwrap_err();
        assert_eq!(error.to_string(), "not a regular file");
        let error = read_regular(Path::new("/dev/zero"), 64, Symlinks::Follow).unwrap_err();
        assert_eq!(error.to_string(), "not a regular file");
        let big = tmp.write("big", &"x".repeat(65));
        let error = read_regular(&big, 64, Symlinks::Follow).unwrap_err();
        assert_eq!(error.to_string(), "larger than 64 bytes");
        assert_eq!(read_regular(&big, 65, Symlinks::Follow).unwrap().len(), 65);
    }
}
