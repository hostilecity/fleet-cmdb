//! Filesystem steps for the installer (P1-A10): atomic writes with the final mode set before any content
//! is written, symlink swaps by rename, and checks that refuse unsafe existing paths (symlinks where a
//! real file or directory belongs, other owners, group- or world-writable directories).
//!
//! Nothing here follows a symlink it did not create, and nothing changes the mode or owner of an
//! existing path: an unsafe path is refused with a message saying how to fix it.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// Marks the installer's temporary files, so a later run can remove any left by an interrupted one.
pub const TEMP_MARKER: &str = ".fleet-agent-tmp-";

fn temp_path(path: &Path) -> PathBuf {
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
    fn write_atomic_sets_the_mode_and_leaves_no_temporary_file() {
        let dir = TempDir::new();
        let path = dir.path("config.toml");
        write_atomic(&path, b"one", 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"one");
        assert_eq!(mode(&path), 0o600);
        // Replacing an existing, more open file gives the new file exactly the requested mode.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_atomic(&path, b"two", 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        assert_eq!(mode(&path), 0o600);
        write_atomic(&dir.path("tool"), b"#!", 0o755).unwrap();
        assert_eq!(mode(&dir.path("tool")), 0o755);
        let names: Vec<_> = fs::read_dir(dir.root())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
    }

    #[test]
    fn a_failed_write_leaves_the_old_file_and_no_temporary_file() {
        let dir = TempDir::new();
        // The destination is a directory, so the final rename fails after the data was written.
        let path = dir.path("config.toml");
        fs::create_dir(&path).unwrap();
        assert!(write_atomic(&path, b"secret", 0o600).is_err());
        assert!(path.is_dir());
        let names: Vec<_> = fs::read_dir(dir.root())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("config.toml")]);
    }

    #[test]
    fn write_atomic_replaces_a_symlink_without_writing_through_it() {
        let dir = TempDir::new();
        let target = dir.write("elsewhere", "untouched");
        let link = dir.path("config.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        write_atomic(&link, b"new", 0o600).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
        assert_eq!(kind(&link).unwrap(), Kind::File);
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
    fn stale_temporary_files_are_removed() {
        let dir = TempDir::new();
        dir.write(&format!(".config.toml{TEMP_MARKER}1-0"), "secret");
        dir.write("config.toml", "keep");
        dir.write(&format!(".other{TEMP_MARKER}1-0"), "not ours");
        assert_eq!(remove_stale_temps(dir.root(), "config.toml").unwrap(), 1);
        assert!(dir.path("config.toml").exists());
        assert!(dir.path(&format!(".other{TEMP_MARKER}1-0")).exists());
        assert_eq!(remove_stale_temps(&dir.path("absent"), "x").unwrap(), 0);
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
