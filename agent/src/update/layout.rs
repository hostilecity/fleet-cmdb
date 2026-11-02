//! Where the updater keeps things (ADR 0018, P1-PACKAGING).
//!
//! ```text
//! <lib>/versions/<version>/fleet-agent     installed versions, side by side
//! <lib>/current  -> versions/<version>      the version systemd starts
//! <lib>/previous -> versions/<older>        the version the last update replaced (the rollback target)
//! <state>/update/<version>/                 a release being staged: manifest, signature, binary
//! <state>/update/backup/                    the state records, copied before the switch
//! <state>/update.json                       the update in progress (its absence means none)
//! <state>/update-confirmed.json             written by the new version after its first acknowledged heartbeat
//! <state>/update-result.json                an outcome waiting to be accepted by the server
//! <state>/update.lock                       held (flock) by the supervisor for as long as it runs
//! ```
//!
//! `<lib>` is `/usr/lib/fleet-agent`. The running agent finds it from where its own binary is:
//! `<lib>/versions/<its own version>/fleet-agent`. Nothing about the layout comes from the server.

use std::io;
use std::path::{Path, PathBuf};

use crate::AGENT_VERSION;
use crate::collect::{HostSystem, System};

/// The binary's name inside a version directory.
pub const BINARY_NAME: &str = "fleet-agent";

/// The transient unit the supervisor runs as. Only one can exist at a time.
pub const SUPERVISOR_UNIT: &str = "fleet-agent-update";

/// The state records of the updater. None of them is part of the state a rollback restores.
pub const RECORD_FILE: &str = "update.json";
pub const MARKER_FILE: &str = "update-confirmed.json";
pub const RESULT_FILE: &str = "update-result.json";
pub const LOCK_FILE: &str = "update.lock";

#[derive(Debug, Clone)]
pub struct Layout {
    pub lib_dir: PathBuf,
    pub state_dir: PathBuf,
}

impl Layout {
    pub fn new(lib_dir: impl Into<PathBuf>, state_dir: impl Into<PathBuf>) -> Self {
        Self {
            lib_dir: lib_dir.into(),
            state_dir: state_dir.into(),
        }
    }

    /// The layout of the agent whose binary is `exe`, or `None` if `exe` is not
    /// `<lib>/versions/<this agent's version>/fleet-agent` (a binary run from a build directory, say,
    /// which has nothing to switch and nothing to roll back to).
    pub fn detect(exe: &Path, state_dir: &Path) -> Option<Self> {
        if exe.file_name()? != BINARY_NAME {
            return None;
        }
        let version_dir = exe.parent()?;
        if version_dir.file_name()? != AGENT_VERSION {
            return None;
        }
        let versions = version_dir.parent()?;
        if versions.file_name()? != "versions" {
            return None;
        }
        Some(Self::new(versions.parent()?, state_dir))
    }

    pub fn versions_dir(&self) -> PathBuf {
        self.lib_dir.join("versions")
    }
    pub fn current(&self) -> PathBuf {
        self.lib_dir.join("current")
    }
    pub fn previous(&self) -> PathBuf {
        self.lib_dir.join("previous")
    }
    pub fn version_dir(&self, version: &str) -> PathBuf {
        self.versions_dir().join(version)
    }
    pub fn binary(&self, version: &str) -> PathBuf {
        self.version_dir(version).join(BINARY_NAME)
    }
    pub fn update_dir(&self) -> PathBuf {
        self.state_dir.join("update")
    }
    pub fn staging(&self, version: &str) -> PathBuf {
        self.update_dir().join(version)
    }
    pub fn backup_dir(&self) -> PathBuf {
        self.update_dir().join("backup")
    }
}

/// `text` as a release version that is safe to use as a directory name: strict SemVer, no build
/// metadata, written canonically. Everything that becomes a path component goes through this.
pub fn parse_version(text: &str) -> Option<semver::Version> {
    let version = semver::Version::parse(text).ok()?;
    (version.build.is_empty() && version.to_string() == text && text.len() <= 64).then_some(version)
}

/// The version `link` (`current` or `previous`) points to, from its `versions/<version>` target.
pub fn link_version(link: &Path) -> Option<String> {
    let target = std::fs::read_link(link).ok()?;
    let name = target.file_name()?.to_str()?;
    (target.parent()? == Path::new("versions") && parse_version(name).is_some())
        .then(|| name.to_owned())
}

/// The kernel's id of the current boot, which changes on every restart of the VM (read and checked as
/// the collectors read it).
pub fn boot_id() -> Option<String> {
    let bytes = std::fs::read("/proc/sys/kernel/random/boot_id").ok()?;
    crate::collect::parse_boot_id(&bytes).ok()
}

/// Free bytes available to unprivileged writers on the file system holding `path` (the collectors'
/// `statvfs`).
pub fn free_bytes(path: &Path) -> io::Result<u64> {
    let stats = HostSystem.statvfs(path)?;
    Ok(stats.blocks_available.saturating_mul(stats.fragment_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    #[test]
    fn the_layout_is_found_from_the_binary_only_when_it_is_where_an_installed_version_lives() {
        let state = Path::new("/var/lib/fleet-agent");
        let exe = PathBuf::from(format!(
            "/usr/lib/fleet-agent/versions/{AGENT_VERSION}/fleet-agent"
        ));
        let layout = Layout::detect(&exe, state).unwrap();
        assert_eq!(layout.lib_dir, Path::new("/usr/lib/fleet-agent"));
        assert_eq!(layout.current(), Path::new("/usr/lib/fleet-agent/current"));
        for other in [
            "/home/dev/fleet-cmdb/agent/target/release/fleet-agent".to_owned(),
            "/usr/lib/fleet-agent/versions/9.9.9/fleet-agent".to_owned(),
            format!("/usr/lib/fleet-agent/{AGENT_VERSION}/fleet-agent"),
            format!("/usr/lib/fleet-agent/versions/{AGENT_VERSION}/other"),
        ] {
            assert!(
                Layout::detect(Path::new(&other), state).is_none(),
                "{other}"
            );
        }
    }

    #[test]
    fn only_canonical_versions_become_path_components() {
        assert!(parse_version("1.2.3").is_some());
        assert!(parse_version("1.3.0-rc.1").is_some());
        for bad in [
            "",
            "1.2",
            "../1.2.3",
            "1.2.3/..",
            "1.2.3+build",
            "01.2.3",
            "v1.2.3",
            " 1.2.3",
            "1.2.3\n",
        ] {
            assert!(parse_version(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn link_versions_are_read_from_the_versions_target() {
        let dir = TempDir::new();
        let link = dir.path("current");
        std::os::unix::fs::symlink("versions/1.2.3", &link).unwrap();
        assert_eq!(link_version(&link).as_deref(), Some("1.2.3"));
        let odd = dir.path("odd");
        std::os::unix::fs::symlink("/etc/passwd", &odd).unwrap();
        assert_eq!(link_version(&odd), None);
        assert_eq!(link_version(&dir.path("missing")), None);
    }

    #[test]
    fn free_bytes_reports_something_for_a_real_directory() {
        let dir = TempDir::new();
        assert!(free_bytes(dir.root()).unwrap() > 0);
        assert!(free_bytes(&dir.path("missing")).is_err());
    }
}
