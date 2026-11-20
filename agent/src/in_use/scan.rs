//! The optional library-use scan (VT-A02, threat model F-13): which packages' files running processes
//! map, which still map a deleted (replaced) version of one, and which packages the scan can judge at
//! all.
//!
//! Reading another process's `/proc/<pid>/maps` needs `CAP_SYS_PTRACE` unless it runs as the same user
//! with no more capabilities. That capability allows attaching to and reading the memory of every
//! process, so it is **never in the agent's unit** (ADR 0032 point 9). Instead, when the VM's local
//! config enables it (`[packages] library_scan = true`), the agent starts this binary in scan mode as a
//! transient oneshot (`systemd-run`, [`PROPERTIES`]): `CAP_SYS_PTRACE` alone, no network
//! (`PrivateNetwork=yes`, `IPAddressDeny=any`, only `AF_UNIX`), a read-only filesystem with home
//! directories, the agent's config, and its state hidden, only the process entries of `/proc`
//! (`ProcSubset=pid`), at most 30 s (`RuntimeMaxSec=`, which systemd enforces), and no input: no
//! argument but the mode, nothing from the server. Its result goes to the agent over standard output
//! (`--pipe`), so it needs no writable path at all. It runs at most once an hour, whatever asks for a
//! report ([`Memo`], owner decision 2026-11-20); reports in between carry the last result and its time.
//!
//! The scan ([`main`]) reads at most [`MAX_PROCESSES`] processes' maps and [`MAX_PATHS`] distinct mapped
//! files under the package-managed prefixes (`/usr`, `/bin`, `/sbin`, `/lib*`), maps them to packages
//! through dpkg's file lists ([`super::owners`]), and prints the package names with a `stale` flag.
//!
//! **What it can prove (owner decision 2026-11-20).** Python, Perl, Ruby, Node, and Java read their code
//! with `read(2)` rather than mapping it, so a package of such code can be in use with nothing of it in
//! any process's maps. The scan therefore also lists `native`: the packages it can judge, those that ship
//! at least one ELF executable or shared library and no interpreted code (no script in a `bin` directory,
//! no file with a [`INTERPRETED`] extension), and none of whose code files it could not read. Only a
//! package in `native` and not in `libraries` may be called idle. Nothing else leaves the scan: no paths,
//! no process ids.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime};

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

/// The scan unit's fixed properties: `CAP_SYS_PTRACE` alone. Of the agent's units it is the only one that
/// runs routinely with that capability and the only one that reads other processes' maps; the
/// `apply_package_updates` task units and `fleet-agent-rollback.service` set no capability bound at all,
/// by design (`docs/operations/agent-task-privileges.md`). Its name,
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
    "--property=CapabilityBoundingSet=CAP_SYS_PTRACE",
    "--property=NoNewPrivileges=yes",
    "--property=PrivateNetwork=yes",
    "--property=IPAddressDeny=any",
    "--property=RestrictAddressFamilies=AF_UNIX",
    "--property=ProtectSystem=strict",
    "--property=ProtectHome=yes",
    "--property=ProcSubset=pid",
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

/// What one scan found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    pub libraries: Vec<Library>,
    /// The packages the scan can judge: native code only ([module documentation](self)).
    pub native: Vec<String>,
}

/// A scan's result and when it ran, kept for an hour (owner decision 2026-11-20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scanned {
    pub result: Result<Output, String>,
    /// RFC 3339, the agent's clock.
    pub at: String,
}

/// The last scan, so it runs at most once per [`EVERY`], however often a report is asked for (by the
/// schedule, the heartbeat's `report_request`, or the `refresh_reports` task). A failed scan is kept too,
/// so a scan that fails is not retried more often either.
#[derive(Debug, Default)]
pub struct Memo {
    last: Option<(Instant, Scanned)>,
}

/// The least time between two scans.
pub const EVERY: Duration = Duration::from_secs(3600);

impl Memo {
    /// The last scan if it is younger than [`EVERY`] at `now`, else a new one from `run`.
    pub fn get(&mut self, now: Instant, run: impl FnOnce() -> Scanned) -> Scanned {
        match &self.last {
            Some((at, scanned)) if now.saturating_duration_since(*at) < EVERY => scanned.clone(),
            _ => {
                let scanned = run();
                self.last = Some((now, scanned.clone()));
                scanned
            }
        }
    }
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

/// Runs the scan unit now and reads its result, stamped with the time it started.
pub fn run(host: &dyn Host, binary: &str, stop: Option<&crate::shutdown::Shutdown>) -> Scanned {
    let at = crate::report::rfc3339(SystemTime::now());
    Scanned {
        result: run_unit(host, binary, stop),
        at,
    }
}

fn run_unit(
    host: &dyn Host,
    binary: &str,
    stop: Option<&crate::shutdown::Shutdown>,
) -> Result<Output, String> {
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
pub fn parse_output(output: &[u8]) -> Result<Output, String> {
    let mut parsed: Output = serde_json::from_slice(output)
        .map_err(|_| "the library scan printed something that is not its result".to_owned())?;
    let mut seen = HashSet::new();
    let mut seen_native = HashSet::new();
    if parsed.libraries.len() > MAX_LIBRARIES
        || parsed.native.len() > MAX_LIBRARIES
        || parsed
            .libraries
            .iter()
            .any(|l| !crate::packages::valid_name(&l.package) || !seen.insert(l.package.clone()))
        || parsed
            .native
            .iter()
            .any(|n| !crate::packages::valid_name(n) || !seen_native.insert(n.clone()))
    {
        return Err("the library scan's result does not fit the contract".into());
    }
    parsed.libraries.sort_by(|a, b| a.package.cmp(&b.package));
    parsed.native.sort();
    Ok(parsed)
}

/// The real host for the scan, reading file heads directly instead of on a thread per call: the scan
/// reads thousands of them, and its unit's `RuntimeMaxSec=` already bounds a read that hangs.
pub struct ScanHost(pub RealHost);

impl Host for ScanHost {
    fn stat(&self, path: &std::path::Path) -> std::io::Result<crate::facts::host::Stat> {
        self.0.stat(path)
    }
    fn read(&self, path: &std::path::Path, max: u64) -> std::io::Result<Vec<u8>> {
        self.0.read(path, max)
    }
    fn list(&self, dir: &std::path::Path, max: usize) -> std::io::Result<Vec<String>> {
        self.0.list(dir, max)
    }
    fn run(&self, command: &Command) -> Result<Vec<u8>, crate::facts::host::RunError> {
        self.0.run(command)
    }
    fn head(&self, path: &std::path::Path, bytes: usize) -> std::io::Result<Vec<u8>> {
        crate::fsx::read_head(path, bytes)
    }
}

/// `fleet-agent library-scan`: run by the transient unit only. Prints the result on standard output.
pub fn main() -> ExitCode {
    let host = ScanHost(RealHost::new());
    match scan(&host) {
        Ok(output) => {
            let text = serde_json::to_string(&output).unwrap_or_default();
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

/// File name endings of interpreted code, which runs without being mapped.
pub const INTERPRETED: &[&str] = &[
    ".py", ".pyc", ".pyo", ".pyz", ".pm", ".pl", ".rb", ".js", ".mjs", ".cjs", ".jar", ".class",
    ".war", ".php", ".lua", ".tcl",
];

/// Where dpkg-managed code lives. Mapped files elsewhere (a user's home, `/tmp`, `/srv`) belong to no
/// package, so they are not counted toward [`MAX_PATHS`].
fn package_managed(path: &str) -> bool {
    ["/usr/", "/bin/", "/sbin/", "/lib"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// A file a package ships that could be native code: anything in a `bin`, `sbin`, or `libexec`
/// directory, or a shared library (`*.so`, `*.so.*`).
fn code_candidate(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or("");
    path.contains("/bin/")
        || path.contains("/sbin/")
        || path.contains("/libexec/")
        || name.ends_with(".so")
        || name.contains(".so.")
}

/// Interpreted code a package ships; its documentation's examples (`/usr/share/doc`) are not code.
fn interpreted(path: &str) -> bool {
    !path.starts_with("/usr/share/doc/") && INTERPRETED.iter().any(|end| path.ends_with(end))
}

/// The scan itself, on any host.
pub fn scan(host: &dyn Host) -> Result<Output, String> {
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
            if package_managed(&file) {
                *mapped.entry(file).or_insert(false) |= deleted;
            }
        }
        if mapped.len() > MAX_PATHS {
            return Err(format!(
                "processes map more than {MAX_PATHS} files, more than the scan reads"
            ));
        }
    }

    // One pass over dpkg's file lists: the owners of the mapped files, and each package's code files.
    let wanted: HashSet<String> = mapped.keys().cloned().collect();
    let lookup = super::owners::lookup(&wanted);
    let mut owners = HashMap::new();
    let mut not_native: HashSet<String> = HashSet::new();
    let mut candidates: BTreeMap<String, Vec<String>> = BTreeMap::new();
    super::owners::each_list(&ctx, |package, lines| {
        for line in lines {
            super::owners::note(&lookup, line, package, &mut owners);
            if interpreted(line) {
                not_native.insert(package.to_owned());
            } else if code_candidate(line) {
                candidates
                    .entry(package.to_owned())
                    .or_default()
                    .push(line.to_owned());
            }
        }
        true
    })?;
    let mut native = BTreeSet::new();
    for (package, files) in candidates {
        if not_native.contains(&package) {
            continue;
        }
        if judge(&ctx, &files) == Some(true) {
            native.insert(package);
        }
    }

    let mut packages: BTreeMap<String, bool> = BTreeMap::new();
    for (file, deleted) in mapped {
        if let Some(package) = owners.get(&file) {
            *packages.entry(package.clone()).or_insert(false) |= deleted;
        }
    }
    if packages.len() > MAX_LIBRARIES || native.len() > MAX_LIBRARIES {
        return Err(format!("more than {MAX_LIBRARIES} packages to name"));
    }
    Ok(Output {
        libraries: packages
            .into_iter()
            .map(|(package, stale)| Library { package, stale })
            .collect(),
        native: native.into_iter().collect(),
    })
}

/// Whether a package's code files are native only: `Some(true)` with an ELF file and no script,
/// `Some(false)` with a script (`#!`) or no ELF file at all, `None` when a code file could not be read
/// (it cannot be judged). Directories, symlinks (alternatives), and files gone meanwhile are skipped.
fn judge(ctx: &Ctx, files: &[String]) -> Option<bool> {
    let mut elf = false;
    for file in files {
        match ctx.head(file, 4) {
            Ok(head) if head == b"\x7fELF" => elf = true,
            Ok(head) if head.starts_with(b"#!") => return Some(false),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(_) => {}
        }
    }
    Some(elf)
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
