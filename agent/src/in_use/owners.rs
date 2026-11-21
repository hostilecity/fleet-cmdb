//! Which binary package owns a file: dpkg's file lists, `/var/lib/dpkg/info/<package>[:<arch>].list`,
//! read-only, one at a time (VT-A01, VT-A02). No command is run.
//!
//! Debian merged `/bin`, `/sbin`, and `/lib*` into `/usr`, but a package's list may still name a file by
//! its old path, so each path is also looked up by its other spelling ([`aliases`]).

use std::collections::{HashMap, HashSet};

use crate::facts::Ctx;

pub const DPKG_INFO: &str = "/var/lib/dpkg/info";
/// Most entries in the info directory (about six files per package, 20,000 packages at most).
const MAX_INFO_ENTRIES: usize = 200_000;
/// Largest list read; the biggest Debian lists (kernel headers, firmware) are a few MiB.
const MAX_LIST_BYTES: u64 = 64 * 1024 * 1024;

const MERGED: [&str; 6] = ["bin", "sbin", "lib", "lib32", "lib64", "libx32"];

/// `path` and its other spelling across the `/usr` merge, if it has one.
pub fn aliases(path: &str) -> Vec<String> {
    let mut out = vec![path.to_owned()];
    for dir in MERGED {
        if let Some(rest) = path.strip_prefix(&format!("/usr/{dir}/")) {
            out.push(format!("/{dir}/{rest}"));
        } else if let Some(rest) = path.strip_prefix(&format!("/{dir}/")) {
            out.push(format!("/usr/{dir}/{rest}"));
        }
    }
    out
}

/// Calls `each` with every package's name and its file list's lines, in name order, until it returns
/// `false`. An unreadable info directory or list is an error: a file whose package is not known would
/// make a package look unused.
///
/// The lists are read in name order, so the lists of one package's architectures (`libfoo:amd64.list`,
/// `libfoo:i386.list`) come one after another. A line that is not UTF-8 is passed with U+FFFD in place
/// of the bytes it cannot read, so a caller can tell (review of #268, N5).
pub fn each_list(
    ctx: &Ctx,
    mut each: impl FnMut(&str, &mut dyn Iterator<Item = std::borrow::Cow<'_, str>>) -> bool,
) -> Result<(), String> {
    let mut names = ctx
        .list(DPKG_INFO, MAX_INFO_ENTRIES)
        .map_err(|e| crate::facts::io_reason(DPKG_INFO, &e))?;
    names.sort();
    for name in names {
        let Some(package) = name.strip_suffix(".list") else {
            continue;
        };
        let package = package.split(':').next().unwrap_or("");
        if !crate::packages::valid_name(package) {
            continue;
        }
        let path = format!("{DPKG_INFO}/{name}");
        let bytes = ctx
            .read(&path, MAX_LIST_BYTES)
            .map_err(|e| crate::facts::io_reason(&path, &e))?;
        let mut lines = bytes.split(|b| *b == b'\n').map(String::from_utf8_lossy);
        if !each(package, &mut lines) {
            break;
        }
    }
    Ok(())
}

/// The package that owns each of `wanted`, for those some package owns. The lists are read in name
/// order and the first owner is kept.
pub fn owners(ctx: &Ctx, wanted: &HashSet<String>) -> Result<HashMap<String, String>, String> {
    let lookup = lookup(wanted);
    let mut found = HashMap::new();
    if lookup.is_empty() {
        return Ok(found);
    }
    each_list(ctx, |package, lines| {
        for line in lines {
            note(&lookup, &line, package, &mut found);
        }
        found.len() < wanted.len()
    })?;
    Ok(found)
}

/// Each spelling of each wanted path ([`aliases`]), to the wanted paths it stands for.
pub fn lookup(wanted: &HashSet<String>) -> HashMap<String, Vec<&String>> {
    let mut lookup: HashMap<String, Vec<&String>> = HashMap::new();
    for path in wanted {
        for alias in aliases(path) {
            lookup.entry(alias).or_default().push(path);
        }
    }
    lookup
}

/// Records `package` as the owner of the wanted paths `line` spells, unless one was found first.
pub fn note(
    lookup: &HashMap<String, Vec<&String>>,
    line: &str,
    package: &str,
    found: &mut HashMap<String, String>,
) {
    if let Some(originals) = lookup.get(line) {
        for original in originals {
            found
                .entry((*original).clone())
                .or_insert_with(|| package.to_owned());
        }
    }
}
