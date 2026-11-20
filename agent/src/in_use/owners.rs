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

/// The package that owns each of `wanted`, for those some package owns. The lists are read in name
/// order and the first owner is kept. An unreadable info directory or list is an error: a file whose
/// package is not known would make a package look unused.
pub fn owners(ctx: &Ctx, wanted: &HashSet<String>) -> Result<HashMap<String, String>, String> {
    let mut lookup: HashMap<String, Vec<&String>> = HashMap::new();
    for path in wanted {
        for alias in aliases(path) {
            lookup.entry(alias).or_default().push(path);
        }
    }
    let mut found = HashMap::new();
    if lookup.is_empty() {
        return Ok(found);
    }
    let names = ctx
        .list(DPKG_INFO, MAX_INFO_ENTRIES)
        .map_err(|e| crate::facts::io_reason(DPKG_INFO, &e))?;
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
        for line in bytes.split(|b| *b == b'\n') {
            let Ok(line) = std::str::from_utf8(line) else {
                continue;
            };
            if let Some(originals) = lookup.get(line) {
                for original in originals {
                    found
                        .entry((*original).clone())
                        .or_insert_with(|| package.to_owned());
                }
            }
        }
        if found.len() == wanted.len() {
            break;
        }
    }
    Ok(found)
}
