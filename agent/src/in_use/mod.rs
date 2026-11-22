//! What running processes use, for vulnerability triage (FR-2.6, VT-APPLICABILITY, ADR 0032 point 9):
//! exposure (N4) and the escalation of packages that listening processes load. Sent in the package
//! report as `in_use`; the server decides what it means.
//!
//! # Listening services and running services (VT-A01): no new privilege
//!
//! 1. The listening TCP sockets and bound UDP sockets, from `/proc/net/{tcp,tcp6,udp,udp6}`
//!    ([`sockets`]).
//! 2. Each socket's cgroup id, from the kernel's `sock_diag` netlink interface ([`netlink`],
//!    [`crate::facts::host::Host::socket_cgroups`]), and the cgroup's path: the directory under
//!    `/sys/fs/cgroup` whose inode number is that id ([`crate::facts::host::Host::directories`]).
//! 3. The path's systemd service ([`units::unit_of`]); a socket systemd itself holds (socket activation)
//!    is matched with `systemctl list-sockets`.
//! 4. The running services (`systemctl list-units`), and each service's main executable (`systemctl
//!    show --property=Id,ExecStart`, the unit names after `--`).
//! 5. The executable's binary package, from dpkg's file lists ([`owners`]).
//!
//! All of it is readable under the agent's unit as it is: `/proc/net` and `/sys/fs/cgroup` are read-only
//! there, `AF_NETLINK` is already allowed (for `getifaddrs`), and `systemctl` already runs. The unit does
//! not change and its `systemd-analyze security` exposure stays 1.9 (`scripts/check-unit.sh`).
//!
//! The report names binary packages and classes only: `listening` (each package with `network` when
//! any of its sockets is on a non-loopback address, else `loopback`), `services` (the packages of
//! running services' executables), and `unnamed_listeners`, the sockets counted but not named (not in a
//! systemd service, such as a container or a user session, or an executable no package owns). Never a
//! process id, command line, user name, address, or port.
//!
//! If the sockets, their cgroups, the services, or the file lists cannot be read whole, `in_use` is
//! `null` with a warning, rather than a partial answer. Bounded: at most
//! [`MAX_SOCKETS`] sockets and [`MAX_UNITS`] units, within [`BUDGET`].
//!
//! # Library use (VT-A02): optional, off by default
//!
//! With `[packages] library_scan = true` in the VM's local config, the scan unit ([`scan`]), at most once
//! an hour, also lists every package whose files running processes map (`libraries`, with which are
//! stale) and every package a process that holds a listening socket maps (`loaded_by_listeners`, with
//! that process's program's package and the socket's class). That short-lived unit, with no network, is
//! the only agent unit that reads other processes' maps and descriptors, with `CAP_SYS_PTRACE` alone.
//! `complete` says whether it ran.
//!
//! # What the lists prove (owner decision 2026-11-21)
//!
//! Every list is positive evidence only, and nothing is ever called idle from it: a snapshot cannot see
//! short-lived helpers, cron jobs, or sessions. A service is named by its `ExecStart=` executable's
//! package, so a wrapper hides the program it starts (`pg_ctlcluster` of `postgresql-common` for
//! PostgreSQL, `sh -c`, `env`, an interpreter); the scan, which reads `/proc/<pid>/exe`, names the real
//! program's package as a listener.

pub mod netlink;
pub mod owners;
pub mod scan;
pub mod sockets;
pub mod units;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io;
use std::time::Duration;

use serde::Serialize;

use crate::facts::Ctx;
use crate::facts::host::{Command, Host};
use crate::shutdown::Shutdown;
use scan::{Library, ListenerUse};
use sockets::Socket;
use units::Owner;

/// The warning when the scan ran but this kernel cannot tell which processes hold a socket (fifth
/// review of #268, S4).
pub const UNSUPPORTED_KERNEL: &str = "the library scan cannot tell which processes listen on this kernel: its fdinfo has no inode (Linux 5.14 or later is needed, so Debian 11's 5.10 is not enough); no package is escalated";

/// The whole collection's budget, the scan apart.
pub const BUDGET: Duration = Duration::from_secs(10);
pub const MAX_SOCKETS: usize = 10_000;
pub const MAX_UNITS: usize = 1_000;
/// Largest `/proc/net` file read (about 150 bytes a socket, established ones included).
const MAX_PROC_NET_BYTES: u64 = 32 * 1024 * 1024;
/// Most cgroup directories walked.
const MAX_CGROUPS: usize = 20_000;
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SYSTEMCTL: &[&str] = &["/usr/bin/systemctl", "/bin/systemctl"];
/// Units per `systemctl show`, so the command line stays short.
const CHUNK: usize = 40;

/// Whether the library scan is enabled, and with which binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scan {
    Off,
    /// The agent's own binary, or why it is not known.
    On(Result<String, String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Listening {
    pub package: String,
    pub class: &'static str,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Unnamed {
    pub network: usize,
    pub loopback: usize,
}

/// The contract's `in_use` object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InUse {
    pub listening: Vec<Listening>,
    pub services: Vec<String>,
    pub unnamed_listeners: Unnamed,
    pub library_scan: &'static str,
    pub libraries: Option<Vec<Library>>,
    /// The packages processes that hold a listening socket map, by listener; `None` unless the scan ran
    /// on a kernel that can tell (5.14 or later).
    pub loaded_by_listeners: Option<Vec<ListenerUse>>,
    /// When the scan whose result this is ran, or was last tried; `None` when it is off.
    pub scanned_at: Option<String>,
    pub complete: bool,
}

/// What [`collect`] found: `in_use`, or `None`, and warnings for the report (field `in_use`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Collected {
    pub in_use: Option<InUse>,
    pub warnings: Vec<String>,
}

/// Collects what is in use. Never fails: what cannot be read is a warning. The library scan runs only
/// when `memo` holds none younger than an hour ([`scan::Memo`]).
pub fn collect(
    host: &dyn Host,
    scan: &Scan,
    memo: &mut scan::Memo,
    stop: Option<&Shutdown>,
) -> Collected {
    let mut ctx = Ctx::new(host, BUDGET);
    if let Some(stop) = stop {
        ctx = ctx.stopping_on(stop);
    }
    let mut warnings = Vec::new();
    let mut in_use = match services(&ctx) {
        Ok(in_use) => in_use,
        Err(why) => {
            warnings.push(why);
            return Collected {
                in_use: None,
                warnings,
            };
        }
    };
    if let Scan::On(binary) = scan {
        let scanned = memo.get(std::time::SystemTime::now(), || match binary {
            Ok(binary) => scan::run(host, binary, stop),
            Err(why) => scan::Scanned {
                result: Err(why.clone()),
                at: crate::report::rfc3339(std::time::SystemTime::now()),
            },
        });
        in_use.scanned_at = Some(scanned.at);
        match scanned.result {
            Ok(output) => {
                in_use.library_scan = "ran";
                in_use.libraries = Some(output.libraries);
                if output.loaded_by_listeners.is_none() {
                    warnings.push(UNSUPPORTED_KERNEL.into());
                }
                in_use.loaded_by_listeners = output.loaded_by_listeners;
                in_use.complete = true;
            }
            Err(why) => {
                in_use.library_scan = "failed";
                warnings.push(format!("the library scan gave no result: {why}"));
            }
        }
    }
    Collected {
        in_use: Some(in_use),
        warnings,
    }
}

/// VT-A01: listening and running services, or why they cannot be read whole.
fn services(ctx: &Ctx) -> Result<InUse, String> {
    let sockets = read_sockets(ctx)?;
    let cgroup_of: HashMap<u64, u64> = ctx
        .socket_cgroups(MAX_SOCKETS)
        .map_err(|e| format!("the sockets' cgroups cannot be read (sock_diag): {e}"))?
        .into_iter()
        .map(|s| (s.inode, s.cgroup))
        .collect();
    let wanted: HashSet<u64> = sockets
        .iter()
        .filter_map(|s| cgroup_of.get(&s.inode).copied())
        .collect();
    let path_of: HashMap<u64, String> = if wanted.is_empty() {
        HashMap::new()
    } else {
        cgroup_paths(ctx, &wanted)?
    };
    let owner = |socket: &Socket| {
        cgroup_of
            .get(&socket.inode)
            .and_then(|id| path_of.get(id))
            .map_or(Owner::Other, |path| units::unit_of(path))
    };
    let mut owned: Vec<(Owner, &Socket)> = sockets.iter().map(|s| (owner(s), s)).collect();
    if owned.iter().any(|(o, _)| matches!(o, Owner::Systemd(_))) {
        // All or nothing: without systemd's list, socket-activated services would drop out.
        let activated = activated(ctx).map_err(|why| {
            format!("the sockets systemd holds for socket activation cannot be named: {why}")
        })?;
        for (owner, socket) in &mut owned {
            if let Owner::Systemd(unit) = owner {
                *owner = match unit {
                    Some(unit) => {
                        let only: Vec<units::Activated> = activated
                            .iter()
                            .filter(|a| a.unit == *unit)
                            .cloned()
                            .collect();
                        match_activated(socket, &only)
                    }
                    None => match_activated(socket, &activated),
                };
            }
        }
    }

    let running = crate::facts::systemd::running(ctx)?;
    let mut units: BTreeSet<String> = running
        .iter()
        .filter(|u| units::service_name(u))
        .cloned()
        .collect();
    for (owner, _) in &owned {
        if let Owner::Service(unit) = owner {
            units.insert(unit.clone());
        }
    }
    if units.len() > MAX_UNITS {
        return Err(format!(
            "{} services, more than the {MAX_UNITS} the agent looks at",
            units.len()
        ));
    }
    let executables = exec_paths(ctx, &units)?;
    let wanted: HashSet<String> = executables.values().flatten().cloned().collect();
    let owners = owners::owners(ctx, &wanted)?;
    let packages_of = |unit: &str| -> BTreeSet<String> {
        executables
            .get(unit)
            .into_iter()
            .flatten()
            .filter_map(|path| owners.get(path).cloned())
            .collect()
    };

    let mut classes: BTreeMap<String, bool> = BTreeMap::new(); // package -> network
    let mut unnamed = Unnamed::default();
    for (owner, socket) in &owned {
        let network = !socket.loopback();
        let packages = match owner {
            Owner::Service(unit) => packages_of(unit),
            _ => BTreeSet::new(),
        };
        if packages.is_empty() {
            if network {
                unnamed.network += 1;
            } else {
                unnamed.loopback += 1;
            }
        }
        for package in packages {
            *classes.entry(package).or_insert(false) |= network;
        }
    }
    let services: BTreeSet<String> = running.iter().flat_map(|u| packages_of(u)).collect();
    Ok(InUse {
        listening: classes
            .into_iter()
            .map(|(package, network)| Listening {
                package,
                class: if network { "network" } else { "loopback" },
            })
            .collect(),
        services: services.into_iter().collect(),
        unnamed_listeners: unnamed,
        library_scan: "off",
        libraries: None,
        loaded_by_listeners: None,
        scanned_at: None,
        complete: false,
    })
}

fn read_sockets(ctx: &Ctx) -> Result<Vec<Socket>, String> {
    let mut all = Vec::new();
    for (path, udp) in sockets::SOURCES {
        let bytes = match ctx.read(path, MAX_PROC_NET_BYTES) {
            Ok(bytes) => bytes,
            // IPv6 turned off: no tcp6 or udp6.
            Err(e) if e.kind() == io::ErrorKind::NotFound && path.ends_with('6') => continue,
            Err(e) => return Err(crate::facts::io_reason(path, &e)),
        };
        all.extend(sockets::parse(&bytes, udp).map_err(|e| format!("{path}: {e}"))?);
        if all.len() > MAX_SOCKETS {
            return Err(format!(
                "more than {MAX_SOCKETS} listening sockets, more than the agent looks at"
            ));
        }
    }
    Ok(all)
}

fn activated(ctx: &Ctx) -> Result<Vec<units::Activated>, String> {
    let command = Command::new(
        SYSTEMCTL,
        &[
            "list-sockets",
            "--all",
            "--show-types",
            "--full",
            "--no-legend",
            "--no-pager",
        ],
    );
    let output = ctx
        .run(command)
        .map_err(|e| e.reason("systemctl list-sockets"))?;
    units::parse_list_sockets(&output)
}

/// The service systemd listens on `socket` for, if exactly one is named: an entry of the same protocol
/// and port, on the socket's own address, else on the wildcard address.
fn match_activated(socket: &Socket, activated: &[units::Activated]) -> Owner {
    let same = |a: &&units::Activated| a.udp == socket.udp && a.port == socket.port;
    activated
        .iter()
        .filter(same)
        .find(|a| a.address == Some(socket.address))
        .or_else(|| activated.iter().filter(same).find(|a| a.address.is_none()))
        .and_then(|a| match a.services.as_slice() {
            [one] => Some(Owner::Service(one.clone())),
            _ => None,
        })
        .unwrap_or(Owner::Other)
}

/// The paths of the cgroups in `wanted`, looking only where a socket can be named: `system.slice` and
/// `init.scope` ([`units::unit_of`]). Users' delegated subtrees are not walked, so they cannot make the
/// walk too large.
fn cgroup_paths(ctx: &Ctx, wanted: &HashSet<u64>) -> Result<HashMap<u64, String>, String> {
    let mut found = HashMap::new();
    for top in ["system.slice", "init.scope"] {
        let root = format!("{CGROUP_ROOT}/{top}");
        let dirs = match ctx.directories(&root, MAX_CGROUPS) {
            Ok(dirs) => dirs,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(crate::facts::io_reason(&root, &e)),
        };
        for (inode, path) in dirs {
            if wanted.contains(&inode) {
                let path = if path.is_empty() {
                    top.to_owned()
                } else {
                    format!("{top}/{path}")
                };
                found.insert(inode, path);
            }
        }
    }
    Ok(found)
}

/// Each unit's executables, from `systemctl show` in chunks.
fn exec_paths(ctx: &Ctx, units: &BTreeSet<String>) -> Result<HashMap<String, Vec<String>>, String> {
    let units: Vec<&str> = units.iter().map(String::as_str).collect();
    let mut all = HashMap::new();
    for chunk in units.chunks(CHUNK) {
        let mut args = vec!["show", "--no-pager", "--property=Id,ExecStart", "--"];
        args.extend(chunk.iter().copied());
        let output = ctx
            .run(Command::new(SYSTEMCTL, &args))
            .map_err(|e| e.reason("systemctl show"))?;
        all.extend(units::parse_show(&output, chunk.len())?);
    }
    Ok(all)
}

#[cfg(test)]
mod tests;
