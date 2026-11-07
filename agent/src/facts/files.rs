//! Sensitive file permissions (P2-A03): a `file:<path>` fact is the mode, owner, and group of the
//! file, from `stat(2)` and nothing else.
//!
//! The paths come from the manifest ("the file list is part of the manifest, not hard-coded in the
//! agent"), so this reader works for any path the manifest lists, and treats the list as untrusted:
//! the file is never opened, never read, and never executed, only `stat`ed. That is why `/etc/shadow`
//! and `/etc/gshadow` can be on the list at all: their contents are never touched. A path that is not
//! in canonical form (`..`, `.` or empty components, a trailing slash) is `unsupported`, so the
//! manifest cannot make the agent walk somewhere other than what it names.
//!
//! - `stat` follows a symlink: what matters for a security check is the permission of the file that
//!   will be used, and a link's own mode is always `0777`. A dangling link is reported as no file.
//! - A file or directory that does not exist (or whose parent is not a directory) is `ok` with `null`,
//!   as the manifest says. Permission denied or a timeout is `unreadable` with the reason.
//! - `mode` is the permission bits in octal with the special bits (`0640`, `4755`, `1777`): always at
//!   least three digits, four here.
//! - `owner` and `group` are names from `/etc/passwd` and `/etc/group` (the first entry for an id), or
//!   the numeric id when there is no name, or when the name does not fit the contract (over 64
//!   characters, or containing a control character). The name files are read once per collection, and
//!   only when a file exists; failing to read them only means numeric ids.

use std::io;

use serde_json::json;

use super::users::Names;
use super::{Ctx, Outcome, io_reason};

/// Whether `path` is an absolute path with no empty, `.` or `..` component and no trailing slash.
pub fn canonical(path: &str) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && !path.ends_with('/')
        && path[1..]
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// One outcome for each of `paths`, in order.
pub fn read(ctx: &Ctx, paths: &[&str]) -> Vec<Outcome> {
    let mut names: Option<Names> = None;
    paths
        .iter()
        .map(|path| {
            if !canonical(path) {
                return Outcome::Unsupported(
                    "the path is not in canonical form (no `.`, `..`, or repeated slashes), so this agent will not look at it".into(),
                );
            }
            match ctx.stat(path) {
                Ok(stat) => {
                    let names = names.get_or_insert_with(|| Names::load(ctx));
                    Outcome::Ok(json!({
                        "mode": mode(stat.mode),
                        "owner": name_or_id(names.users.get(&stat.uid), stat.uid),
                        "group": name_or_id(names.groups.get(&stat.gid), stat.gid),
                    }))
                }
                Err(e) if absent(&e) => Outcome::Ok(serde_json::Value::Null),
                Err(e) => Outcome::Unreadable(io_reason(path, &e)),
            }
        })
        .collect()
}

/// Whether the error means there is no such file.
fn absent(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    )
}

/// Permission bits in octal, four digits: `0640`, `4755`.
pub fn mode(bits: u32) -> String {
    format!("{:04o}", bits & 0o7777)
}

/// The name when it fits the contract (1 to 64 characters, no control characters), else the id.
fn name_or_id(name: Option<&String>, id: u32) -> String {
    match name {
        Some(name)
            if (1..=64).contains(&name.chars().count()) && !name.chars().any(char::is_control) =>
        {
            name.clone()
        }
        _ => id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_are_four_octal_digits() {
        assert_eq!(mode(0o640), "0640");
        assert_eq!(mode(0o4755), "4755");
        assert_eq!(mode(0o1777), "1777");
        assert_eq!(mode(0o2755), "2755");
        assert_eq!(mode(0o0), "0000");
        assert_eq!(
            mode(0o100644),
            "0644",
            "file type bits are not part of the mode"
        );
    }

    #[test]
    fn only_canonical_paths_are_looked_at() {
        for path in ["/etc/passwd", "/etc/cron.d", "/boot/grub/grub.cfg", "/a"] {
            assert!(canonical(path), "{path}");
        }
        for path in [
            "",
            "/",
            "etc/passwd",
            "/etc//passwd",
            "/etc/./passwd",
            "/etc/../etc/shadow",
            "/etc/passwd/",
            "/..",
            "/etc/..",
        ] {
            assert!(!canonical(path), "{path:?}");
        }
    }

    #[test]
    fn a_name_that_does_not_fit_becomes_the_numeric_id() {
        assert_eq!(name_or_id(Some(&"root".to_owned()), 0), "root");
        assert_eq!(name_or_id(None, 1234), "1234");
        assert_eq!(name_or_id(Some(&"x".repeat(64)), 5), "x".repeat(64));
        assert_eq!(name_or_id(Some(&"x".repeat(65)), 5), "5");
        assert_eq!(name_or_id(Some(&String::new()), 6), "6");
        assert_eq!(name_or_id(Some(&"a\u{7}b".to_owned()), 7), "7");
    }
}
