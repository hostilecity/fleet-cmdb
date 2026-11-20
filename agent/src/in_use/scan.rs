//! The optional library-use scan (VT-A02, threat model F-13): which packages' files running processes
//! map, and which still map a deleted (replaced) version of one.
//!
//! Reading another process's `/proc/<pid>/maps` needs `CAP_SYS_PTRACE` unless it runs as the same user
//! with no more capabilities. That capability allows attaching to and reading the memory of every
//! process, so it is **never in the agent's unit** (ADR 0032 point 9). Instead, when the VM's local
//! config enables it (`[packages] library_scan = true`), the agent starts this binary in scan mode as a
//! transient oneshot (`systemd-run`, [`PROPERTIES`]): the two capabilities, no network
//! (`PrivateNetwork=yes`, `IPAddressDeny=any`, only `AF_UNIX`), a read-only filesystem with the agent's
//! config and state hidden, at most 30 s (`RuntimeMaxSec=`, which systemd enforces), and no input:
//! no argument but the mode, nothing from the server. Its result goes to the agent over standard output
//! (`--pipe`), so it needs no writable path at all. With the scan off nothing carries the capability.
//!
//! The scan ([`main`]) reads at most [`MAX_PROCESSES`] processes' maps and [`MAX_PATHS`] distinct
//! mapped files, maps them to packages through dpkg's file lists ([`super::owners`]), and prints the
//! package names with a `stale` flag as JSON. Nothing else leaves it: no paths, no process ids.

use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::facts::Ctx;
use crate::facts::host::{Command, Host, RealHost};

pub const SYSTEMD_RUN: &[&str] = &["/usr/bin/systemd-run"];
/// The subcommand the unit runs.
pub const MODE: &str = "library-scan";
/// systemd stops the scan after 30 s (`RuntimeMaxSec=`); the agent waits a little longer for
/// `systemd-run` to return.
const WAIT: Duration = Duration::from_secs(45);
/// The scan's own budget, inside [`RUNTIME_MAX`].
const BUDGET: Duration = Duration::from_secs(25);
pub const MAX_PROCESSES: usize = 4096;
pub const MAX_PATHS: usize = 50_000;
/// The contract's limit on `libraries`.
pub const MAX_LIBRARIES: usize = 20_000;
const MAX_MAPS_BYTES: u64 = 8 * 1024 * 1024;
const MAX_OUTPUT: usize = 4 * 1024 * 1024;

/// The scan unit's fixed properties. Only this unit ever carries `CAP_SYS_PTRACE`. Its name,
/// `fleet-agent-library-scan.service`, is covered by DEC-15's `fleet-agent*` rule, so `restart_service`
/// never touches it.
pub const PROPERTIES: &[&str] = &[
    "--unit=fleet-agent-library-scan.service",
    "--description=Fleet agent library-use scan (VT-A02)",
    "--wait",
    "--pipe",
    "--collect",
    "--quiet",
    "--property=Type=exec",
    "--property=RuntimeMaxSec=30",
    "--property=CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH",
    "--property=NoNewPrivileges=yes",
    "--property=PrivateNetwork=yes",
    "--property=IPAddressDeny=any",
    "--property=RestrictAddressFamilies=AF_UNIX",
    "--property=ProtectSystem=strict",
    "--property=ProtectHome=read-only",
    "--property=InaccessiblePaths=-/etc/fleet-agent -/var/lib/fleet-agent",
    "--property=PrivateTmp=yes",
    "--property=PrivateDevices=yes",
    "--property=PrivateIPC=yes",
    "--property=ProtectKernelTunables=yes",
    "--property=ProtectKernelModules=yes",
    "--property=ProtectKernelLogs=yes",
    "--property=ProtectControlGroups=yes",
    "--property=ProtectClock=yes",
    "--property=ProtectHostname=yes",
    "--property=RestrictNamespaces=yes",
    "--property=RestrictRealtime=yes",
    "--property=RestrictSUIDSGID=yes",
    "--property=LockPersonality=yes",
    "--property=MemoryDenyWriteExecute=yes",
    "--property=SystemCallArchitectures=native",
    "--property=SystemCallFilter=@system-service",
    "--property=SystemCallFilter=~@privileged @resources",
    "--property=SystemCallErrorNumber=EPERM",
    "--property=MemoryMax=128M",
    "--property=MemorySwapMax=0",
    "--property=TasksMax=16",
    "--property=WorkingDirectory=/",
    "--property=StandardInput=null",
];

/// One package a running process maps a file of.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Library {
    pub package: String,
    /// A process maps a deleted version of one of its files.
    pub stale: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Output {
    libraries: Vec<Library>,
}

/// The scan's command line: `systemd-run` with [`PROPERTIES`], then the agent's own binary in scan mode.
pub fn command(binary: &str) -> Command {
    let mut args: Vec<&str> = PROPERTIES.to_vec();
    args.extend(["--", binary, MODE]);
    let mut command = Command::new(SYSTEMD_RUN, &args);
    command.timeout = WAIT;
    command.max_output = MAX_OUTPUT;
    command
}

/// Runs the scan unit and reads its result.
pub fn run(
    host: &dyn Host,
    binary: &str,
    stop: Option<&crate::shutdown::Shutdown>,
) -> Result<Vec<Library>, String> {
    if !binary.starts_with('/') || binary.chars().any(char::is_control) {
        return Err("the agent's own path is not an absolute path".into());
    }
    let mut ctx = Ctx::new(host, WAIT);
    if let Some(stop) = stop {
        ctx = ctx.stopping_on(stop);
    }
    let output = ctx
        .run(command(binary))
        .map_err(|e| e.reason("the library scan unit"))?;
    parse_output(&output)
}

/// The scan's standard output, checked against the contract.
pub fn parse_output(output: &[u8]) -> Result<Vec<Library>, String> {
    let parsed: Output = serde_json::from_slice(output)
        .map_err(|_| "the library scan printed something that is not its result".to_owned())?;
    let mut seen = HashSet::new();
    if parsed.libraries.len() > MAX_LIBRARIES
        || parsed
            .libraries
            .iter()
            .any(|l| !crate::packages::valid_name(&l.package) || !seen.insert(l.package.clone()))
    {
        return Err("the library scan's result does not fit the contract".into());
    }
    let mut libraries = parsed.libraries;
    libraries.sort_by(|a, b| a.package.cmp(&b.package));
    Ok(libraries)
}

/// `fleet-agent library-scan`: run by the transient unit only. Prints the result on standard output.
pub fn main() -> ExitCode {
    let host = RealHost::new();
    match scan(&host) {
        Ok(libraries) => {
            let text = serde_json::to_string(&Output { libraries }).unwrap_or_default();
            let mut out = std::io::stdout().lock();
            if writeln!(out, "{text}").and_then(|()| out.flush()).is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!(
                "fleet-agent library-scan: {}",
                crate::facts::clip_reason(&why)
            );
            ExitCode::FAILURE
        }
    }
}

/// The scan itself, on any host.
pub fn scan(host: &dyn Host) -> Result<Vec<Library>, String> {
    let ctx = Ctx::new(host, BUDGET);
    let pids: Vec<String> = ctx
        .list("/proc", 1_000_000)
        .map_err(|e| crate::facts::io_reason("/proc", &e))?
        .into_iter()
        .filter(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()))
        .collect();
    if pids.len() > MAX_PROCESSES {
        return Err(format!(
            "{} processes are running, more than the {MAX_PROCESSES} the scan reads",
            pids.len()
        ));
    }
    // Path -> mapped deleted (stale) by any process.
    let mut mapped: BTreeMap<String, bool> = BTreeMap::new();
    for pid in &pids {
        let path = format!("/proc/{pid}/maps");
        let bytes = match ctx.read(&path, MAX_MAPS_BYTES) {
            Ok(bytes) => bytes,
            // The process ended meanwhile.
            Err(e)
                if matches!(e.kind(), std::io::ErrorKind::NotFound)
                    || e.raw_os_error() == Some(libc::ESRCH) =>
            {
                continue;
            }
            Err(e) => return Err(crate::facts::io_reason(&path, &e)),
        };
        for (file, deleted) in parse_maps(&bytes) {
            let entry = mapped.entry(file).or_insert(false);
            *entry |= deleted;
        }
        if mapped.len() > MAX_PATHS {
            return Err(format!(
                "processes map more than {MAX_PATHS} files, more than the scan reads"
            ));
        }
    }
    let wanted: HashSet<String> = mapped.keys().cloned().collect();
    let owners = super::owners::owners(&ctx, &wanted)?;
    let mut packages: BTreeMap<String, bool> = BTreeMap::new();
    for (file, deleted) in mapped {
        if let Some(package) = owners.get(&file) {
            *packages.entry(package.clone()).or_insert(false) |= deleted;
        }
    }
    if packages.len() > MAX_LIBRARIES {
        return Err(format!("more than {MAX_LIBRARIES} packages are in use"));
    }
    Ok(packages
        .into_iter()
        .map(|(package, stale)| Library { package, stale })
        .collect())
}

/// The files of one `/proc/<pid>/maps`: `address perms offset dev inode path`, the path from the sixth
/// field on (it may hold spaces), with whether the kernel marks it ` (deleted)`. Anonymous mappings,
/// `[heap]` and the like are left out.
pub fn parse_maps(bytes: &[u8]) -> Vec<(String, bool)> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    for line in text.lines() {
        let mut rest = line;
        for _ in 0..5 {
            rest = rest.trim_start();
            rest = rest.find(' ').map_or("", |at| &rest[at..]);
        }
        let path = rest.trim_start();
        if !path.starts_with('/') {
            continue;
        }
        match path.strip_suffix(" (deleted)") {
            Some(path) => out.push((path.to_owned(), true)),
            None => out.push((path.to_owned(), false)),
        }
    }
    out
}
