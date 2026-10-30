//! Disk facts from `/proc/self/mounts` and `statvfs(3)` (FR-1.3, P1-A05).
//!
//! # Which mounts are reported
//!
//! A mount is a real disk, and reported, when all of these hold:
//!
//! 0. It is visible: no later mount in the table sits on the same mount point or on one of its parent
//!    directories. A mount stacked on top (an overmount) hides the one below, and `statvfs` on that
//!    path would report the top filesystem, so only the top one is considered (review of #64).
//! 1. Its filesystem type is not a pseudo or virtual one ([`PSEUDO_FILESYSTEMS`]: `proc`, `sysfs`,
//!    `tmpfs`, `devtmpfs`, `cgroup2`, container `overlay`, and the like).
//! 2. Its source is a block device, an absolute path under `/dev/`. This also leaves out network
//!    filesystems (NFS, CIFS), whose free space belongs to another machine and whose `statvfs` can
//!    hang when the server is away, and pseudo filesystems missing from the list in rule 1.
//! 3. It is the first mount of that source in mount order. Later mounts of the same device (bind
//!    mounts, a container's bind-mounted `/etc/hosts`, further btrfs subvolumes) show the same space
//!    and are dropped, so space is not counted twice. The kernel lists mounts in the order they were
//!    made, so the original mount comes before its bind mounts.
//!
//! Mount points are unescaped (`\040` space, `\011` tab, `\012` newline, `\134` backslash). A mount
//! point that is not valid UTF-8 is reported with replacement characters. Disks are sorted by mount
//! point. `size_bytes` is `f_blocks * f_frsize` and `free_bytes` is `f_bavail * f_frsize`, the `Size`
//! and `Avail` columns of `df`. The mount list and sizes are stable; free space is volatile (DEC-07).

use std::collections::HashSet;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::system::MAX_SAFE_INTEGER;
use super::{Disk, FsStats};

/// Contract limit on the number of disks.
pub const MAX_DISKS: usize = 64;

/// Most `statvfs` calls in one collection: the first mounts by path, with room for some to fail.
pub const MAX_STATVFS: usize = 2 * MAX_DISKS;

/// Filesystem types that never hold a disk's data.
pub const PSEUDO_FILESYSTEMS: &[&str] = &[
    "aufs",
    "autofs",
    "binfmt_misc",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "devtmpfs",
    "efivarfs",
    "fusectl",
    "hugetlbfs",
    "mqueue",
    "nsfs",
    "overlay",
    "proc",
    "pstore",
    "ramfs",
    "rpc_pipefs",
    "securityfs",
    "selinuxfs",
    "shiftfs",
    "sysfs",
    "tmpfs",
    "tracefs",
];

/// One line of `/proc/self/mounts`, with escapes decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub source: Vec<u8>,
    pub mount_point: Vec<u8>,
    pub fstype: String,
}

impl MountEntry {
    pub fn mount_path(&self) -> PathBuf {
        PathBuf::from(OsStr::from_bytes(&self.mount_point))
    }

    pub fn mount_display(&self) -> String {
        String::from_utf8_lossy(&self.mount_point).into_owned()
    }
}

/// Decodes the octal escapes the kernel writes for space, tab, newline, and backslash (`\040`). A
/// backslash not followed by three octal digits is kept as it is.
pub fn unescape(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0;
    while i < field.len() {
        if field[i] == b'\\'
            && let Some(digits) = field.get(i + 1..i + 4)
            && digits.iter().all(|d| (b'0'..=b'7').contains(d))
        {
            let value = digits
                .iter()
                .fold(0u32, |acc, d| acc * 8 + u32::from(d - b'0'));
            if let Ok(byte) = u8::try_from(value) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(field[i]);
        i += 1;
    }
    out
}

/// Parses `/proc/self/mounts`. Lines with fewer than four fields are skipped; a file with no valid line
/// at all is an error (an empty mount table means the file is not what it should be).
pub fn parse_mounts(bytes: &[u8]) -> Result<Vec<MountEntry>, String> {
    let mut entries = Vec::new();
    for line in bytes.split(|b| *b == b'\n') {
        let mut fields = line.split(|b| *b == b' ').filter(|f| !f.is_empty());
        let (Some(source), Some(mount_point), Some(fstype), Some(_options)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Ok(fstype) = std::str::from_utf8(&unescape(fstype)).map(str::to_owned) else {
            continue;
        };
        let mount_point = unescape(mount_point);
        if !mount_point.starts_with(b"/") {
            continue;
        }
        entries.push(MountEntry {
            source: unescape(source),
            mount_point,
            fstype,
        });
    }
    if entries.is_empty() {
        return Err("no mount entries".to_owned());
    }
    Ok(entries)
}

/// Whether a mount counts as a real disk by rules 1 and 2 in the module documentation.
pub fn is_real(entry: &MountEntry) -> bool {
    !PSEUDO_FILESYSTEMS.contains(&entry.fstype.as_str()) && entry.source.starts_with(b"/dev/")
}

/// The mounts no later mount covers (rule 0), in mount order. The kernel lists mounts in the order
/// they were made, so a mount is hidden when a later entry is at its mount point or at a parent of it.
pub fn visible(entries: Vec<MountEntry>) -> Vec<MountEntry> {
    let mut later: HashSet<Vec<u8>> = HashSet::new();
    let mut kept = Vec::new();
    for entry in entries.into_iter().rev() {
        let hidden = Path::new(OsStr::from_bytes(&entry.mount_point))
            .ancestors()
            .any(|dir| later.contains(dir.as_os_str().as_bytes()));
        later.insert(entry.mount_point.clone());
        if !hidden {
            kept.push(entry);
        }
    }
    kept.reverse();
    kept
}

/// Real mounts, one per source device, in mount order (rules 0 to 3).
pub fn select_real(entries: Vec<MountEntry>) -> Vec<MountEntry> {
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let mut selected = Vec::new();
    for entry in visible(entries) {
        if !is_real(&entry) || seen.contains(&entry.source) {
            continue;
        }
        seen.push(entry.source.clone());
        selected.push(entry);
    }
    selected
}

/// Builds the reported disk, checking the contract's length and range limits.
pub fn to_disk(entry: &MountEntry, stats: FsStats) -> Result<Disk, String> {
    let mount = entry.mount_display();
    if mount.chars().count() > 1024 {
        return Err("mount point longer than 1024 characters".to_owned());
    }
    if entry.fstype.is_empty() || entry.fstype.chars().count() > 64 {
        return Err("filesystem type empty or longer than 64 characters".to_owned());
    }
    let bytes = |blocks: u64| {
        blocks
            .checked_mul(stats.fragment_size)
            .filter(|b| *b <= MAX_SAFE_INTEGER)
            .ok_or_else(|| "size out of range".to_owned())
    };
    let size_bytes = bytes(stats.blocks)?;
    let free_bytes = bytes(stats.blocks_available)?.min(size_bytes);
    Ok(Disk {
        mount,
        filesystem: entry.fstype.clone(),
        size_bytes,
        free_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTS: &[u8] = include_bytes!("../../tests/fixtures/collect/debian13/proc/self/mounts");

    fn mount_points(entries: &[MountEntry]) -> Vec<String> {
        entries.iter().map(MountEntry::mount_display).collect()
    }

    #[test]
    fn unescapes_kernel_octal_escapes() {
        assert_eq!(unescape(br"/srv/media\040files"), b"/srv/media files");
        assert_eq!(
            unescape(br"/mnt/a\011b\012c\134d"),
            b"/mnt/a\tb\nc\\d".to_vec()
        );
        // Not an escape: kept as written.
        assert_eq!(unescape(br"/mnt/x\0"), br"/mnt/x\0".to_vec());
        assert_eq!(unescape(br"/mnt/x\9999"), br"/mnt/x\9999".to_vec());
        assert_eq!(unescape(br"/mnt/x\"), br"/mnt/x\".to_vec());
        // Octal above 255 is not a byte: kept as written.
        assert_eq!(unescape(br"\777"), br"\777".to_vec());
    }

    #[test]
    fn parses_fixture_with_unusual_options_and_escapes() {
        let entries = parse_mounts(MOUNTS).expect("parse");
        let efi = entries
            .iter()
            .find(|e| e.mount_point == b"/boot/efi")
            .expect("efi");
        assert_eq!(efi.fstype, "vfat");
        assert_eq!(efi.source, b"/dev/sda15");
        assert!(entries.iter().any(|e| e.mount_point == b"/srv/media files"));
        assert!(
            entries
                .iter()
                .any(|e| e.mount_point == b"/mnt/back\\slash\ttab")
        );
    }

    #[test]
    fn selects_real_mounts_by_the_documented_rule() {
        let selected = select_real(parse_mounts(MOUNTS).expect("parse"));
        assert_eq!(
            mount_points(&selected),
            [
                "/",
                "/boot/efi",
                "/srv/media files",
                "/mnt/back\\slash\ttab"
            ]
        );
    }

    #[test]
    fn excludes_pseudo_filesystems_even_with_a_dev_source() {
        let entry = |fstype: &str| MountEntry {
            source: b"/dev/fake".to_vec(),
            mount_point: b"/mnt".to_vec(),
            fstype: fstype.to_owned(),
        };
        for pseudo in PSEUDO_FILESYSTEMS {
            assert!(!is_real(&entry(pseudo)), "{pseudo} counted as real");
        }
        assert!(is_real(&entry("ext4")));
        assert!(is_real(&entry("xfs")));
    }

    #[test]
    fn excludes_network_and_sourceless_mounts() {
        let entries = parse_mounts(
            b"nas.example.lan:/export /mnt/nas nfs4 rw 0 0\n//nas/share /mnt/smb cifs rw 0 0\nnone /mnt/x ext4 rw 0 0\n",
        )
        .expect("parse");
        assert!(select_real(entries).is_empty());
    }

    #[test]
    fn deduplicates_bind_mounts_keeping_the_first() {
        let entries = parse_mounts(
            b"/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /srv/data xfs rw 0 0\n/dev/sdb1 /export xfs rw 0 0\n",
        )
        .expect("parse");
        assert_eq!(mount_points(&select_real(entries)), ["/", "/srv/data"]);
    }

    #[test]
    fn an_overmount_hides_the_mount_below_it() {
        // Review of #64: two devices stacked on /srv must not both be reported (statvfs would query
        // the top one twice and the server would reject the duplicate mount).
        let entries = parse_mounts(
            b"/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /srv xfs rw 0 0\n/dev/sdc1 /srv ext4 rw 0 0\n",
        )
        .expect("parse");
        let selected = select_real(entries);
        assert_eq!(mount_points(&selected), ["/", "/srv"]);
        assert_eq!(selected[1].source, b"/dev/sdc1");

        // A mount on a parent directory hides the mounts under it that came before it...
        let entries = parse_mounts(
            b"/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /mnt/a xfs rw 0 0\n/dev/sdc1 /mnt ext4 rw 0 0\n/dev/sdd1 /mnt/b xfs rw 0 0\n",
        )
        .expect("parse");
        // ...but not those made after it, and not a sibling that only shares a name prefix.
        assert_eq!(mount_points(&select_real(entries)), ["/", "/mnt", "/mnt/b"]);
        let entries = parse_mounts(b"/dev/sdb1 /mntx xfs rw 0 0\n/dev/sdc1 /mnt ext4 rw 0 0\n")
            .expect("parse");
        assert_eq!(mount_points(&select_real(entries)), ["/mntx", "/mnt"]);

        // If the first mount of a device is hidden, a visible bind mount of it still counts.
        let entries = parse_mounts(
            b"/dev/sdb1 /srv xfs rw 0 0\n/dev/sdb1 /export xfs rw 0 0\n/dev/sdc1 /srv ext4 rw 0 0\n",
        )
        .expect("parse");
        let selected = select_real(entries);
        assert_eq!(mount_points(&selected), ["/export", "/srv"]);
        assert_eq!(selected[0].source, b"/dev/sdb1");

        // A pseudo filesystem on top hides the disk too: the disk's space is not reachable there.
        let entries =
            parse_mounts(b"/dev/sdb1 /srv xfs rw 0 0\ntmpfs /srv tmpfs rw 0 0\n").expect("parse");
        assert!(select_real(entries).is_empty());
    }

    #[test]
    fn rejects_a_file_with_no_mount_lines() {
        assert!(parse_mounts(b"").is_err());
        assert!(parse_mounts(b"garbage\nmore garbage\n").is_err());
        // Malformed lines are skipped, good ones kept.
        let entries = parse_mounts(b"short line\n/dev/sda1 / ext4 rw 0 0\n").expect("parse");
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn computes_df_figures() {
        let entry = MountEntry {
            source: b"/dev/sda1".to_vec(),
            mount_point: b"/".to_vec(),
            fstype: "ext4".to_owned(),
        };
        let disk = to_disk(
            &entry,
            FsStats {
                fragment_size: 4096,
                blocks: 8_388_608,
                blocks_available: 5_242_880,
            },
        )
        .expect("disk");
        assert_eq!(disk.size_bytes, 34_359_738_368);
        assert_eq!(disk.free_bytes, 21_474_836_480);
        assert!(
            to_disk(
                &entry,
                FsStats {
                    fragment_size: u64::MAX,
                    blocks: 2,
                    blocks_available: 0,
                },
            )
            .is_err()
        );
    }
}
