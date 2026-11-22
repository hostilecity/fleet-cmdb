//! The optional library-use scan (VT-A02, threat model F-13): which packages' files running processes
//! map, which still map a deleted (replaced) version of one, and which ones processes that hold a
//! listening socket map.
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
//! The scan ([`main`]) reads at most [`MAX_PROCESSES`] processes' maps, [`MAX_PATHS`] distinct mapped
//! files under the package-managed prefixes (`/usr`, `/bin`, `/sbin`, `/lib*`) and [`MAX_OTHER_PATHS`]
//! elsewhere, maps every one to each package that lists it ([`super::owners`]; a diverted file marks
//! both), and prints the package names with a `stale` flag. Within its 25 s budget, or it fails.
//!
//! **Positive evidence only (owner decision 2026-11-21, after the fourth review of #268).** "Not
//! continuously running does not equal low risk", and a snapshot cannot see short-lived helpers, cron
//! jobs, or `sftp-server` sessions, so nothing is ever called idle from the scan. What it reports is what
//! it saw: `libraries`, the packages any process maps, and `loaded_by_listeners`, each package a process
//! that holds a listening socket maps (any file of it, ELF or not), with that process's program's package
//! whether the socket is on the network or on loopback only, that process's systemd unit, and the
//! listening sockets it holds (`address:port/protocol`, at most [`MAX_SOCKETS_PER_USE`]), so a reason can
//! name them (#277). A process holds a socket when one of
//! its descriptors (`/proc/<pid>/fd`, readable with `CAP_SYS_PTRACE`) is a listening socket of the host's
//! network namespace (`/proc/1/net/{tcp,tcp6,udp,udp6}`, [`HOST_SOCKETS`]). What the scan misses is
//! simply not reported. Nothing else leaves the scan: no paths, no process ids, no other addresses.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

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

/// One package a process that holds a listening socket maps a file of.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerUse {
    pub package: String,
    /// The package of that process's program; `None` when no package owns it.
    pub listener: Option<String>,
    /// That process's systemd unit (`ssh.service`, a socket unit, `init.scope`), from
    /// `/proc/<pid>/cgroup`; `None` outside `system.slice` and `init.scope`.
    pub service: Option<String>,
    /// `network` when one of the sockets it holds is on a non-loopback address, else `loopback`.
    pub class: String,
    /// The listening sockets those processes hold, `address:port/protocol`, sorted, at most
    /// [`MAX_SOCKETS_PER_USE`] (network ones first, so a truncated list still shows them).
    pub sockets: Vec<String>,
}

/// What one scan found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    pub libraries: Vec<Library>,
    pub loaded_by_listeners: Vec<ListenerUse>,
}

/// A scan's result and when it ran, kept for an hour (owner decision 2026-11-20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scanned {
    pub result: Result<Output, String>,
    /// RFC 3339, the agent's clock.
    pub at: String,
}

/// The last scan, so it runs at most once per [`EVERY`], however often a report is asked for (by the
/// schedule, the heartbeat's `report_request`, or the `refresh_reports` task), and across agent restarts
/// and updates: it is kept in the state directory as [`RECORD`] (mode 0600, written atomically), aged by
/// the wall clock, so a scan older than an hour after a suspend is not reused (owner decision 2026-11-20,
/// re-review of #268, S4). A failed scan is kept too, so a scan that fails is not retried more often
/// either. A record that is missing, corrupt, unreadable, or dated in the future means a new scan; a
/// record that cannot be written is logged, and the scan's result is still used.
#[derive(Debug, Default)]
pub struct Memo {
    dir: Option<std::path::PathBuf>,
    last: Option<Record>,
}

/// The least time between two scans.
pub const EVERY: Duration = Duration::from_secs(3600);
/// The record's name in the state directory.
pub const RECORD: &str = "library-scan.json";
const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;

/// What [`Memo`] keeps: when the scan ran (seconds since the epoch, wall clock), and what it found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Record {
    ran_at: u64,
    at: String,
    output: Option<Output>,
    error: Option<String>,
}

impl Record {
    /// The record as the scan's own output would be checked (third review, N3): its time an RFC 3339
    /// timestamp, its output within the contract, and a failure reason a report can carry. Anything else
    /// is a damaged record, and the scan runs again.
    fn checked(mut self) -> Result<Self, String> {
        if crate::report::parse_rfc3339(&self.at).is_none() {
            return Err("its time is not an RFC 3339 timestamp".into());
        }
        match (self.output.take(), &self.error) {
            (Some(output), None) => self.output = Some(check_output(output)?),
            (None, Some(error)) if !error.is_empty() && error.chars().count() <= 512 => {}
            _ => return Err("it holds neither a result nor a reason".into()),
        }
        Ok(self)
    }

    fn scanned(&self) -> Scanned {
        Scanned {
            result: match (&self.output, &self.error) {
                (Some(output), _) => Ok(output.clone()),
                (None, Some(error)) => Err(error.clone()),
                (None, None) => Err("the last scan left no result".into()),
            },
            at: self.at.clone(),
        }
    }
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Memo {
    /// A memo kept in `dir` (the agent's state directory) as well as in memory.
    pub fn in_dir(dir: &std::path::Path) -> Self {
        Self {
            dir: Some(dir.to_owned()),
            last: None,
        }
    }

    /// The last scan if it ran less than [`EVERY`] before `now` (the wall clock) and not after it, else a
    /// new one from `run`, which is then kept.
    pub fn get(&mut self, now: SystemTime, run: impl FnOnce() -> Scanned) -> Scanned {
        if self.last.is_none() {
            self.last = self.load();
        }
        let now_s = unix_seconds(now);
        if let Some(last) = &self.last
            && last.ran_at <= now_s
            && now_s - last.ran_at < EVERY.as_secs()
        {
            return last.scanned();
        }
        let scanned = run();
        let (output, error) = match &scanned.result {
            Ok(output) => (Some(output.clone()), None),
            Err(error) => (None, Some(crate::facts::clip_reason(error))),
        };
        let record = Record {
            ran_at: now_s,
            at: scanned.at.clone(),
            output,
            error,
        };
        self.store(&record);
        self.last = Some(record);
        scanned
    }

    fn load(&self) -> Option<Record> {
        let dir = self.dir.as_ref()?;
        match crate::state::read_record(dir, RECORD, MAX_RECORD_BYTES) {
            Ok(Some(bytes)) => match serde_json::from_slice::<Record>(&bytes)
                .map_err(|e| e.to_string())
                .and_then(Record::checked)
            {
                Ok(record) => Some(record),
                Err(e) => {
                    tracing::warn!(
                        "the last library scan's record cannot be read ({e}); scanning again"
                    );
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    "the last library scan's record cannot be read ({e}); scanning again"
                );
                None
            }
        }
    }

    fn store(&self, record: &Record) {
        let Some(dir) = &self.dir else {
            return;
        };
        let written = serde_json::to_vec(record)
            .map_err(std::io::Error::other)
            .and_then(|bytes| crate::state::write_record(dir, RECORD, &bytes));
        if let Err(e) = written {
            tracing::warn!(
                "cannot keep the library scan's result in {} ({e}); the next agent start scans again",
                dir.display()
            );
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
    let parsed: Output = serde_json::from_slice(output)
        .map_err(|_| "the library scan printed something that is not its result".to_owned())?;
    check_output(parsed)
}

/// An [`Output`] as the contract allows it: valid package names, a package once in `libraries` and a
/// (package, listener) pair once in `loaded_by_listeners`, a known class, within the limits, sorted. Used
/// on the scan's output and on a kept record alike.
pub fn check_output(mut parsed: Output) -> Result<Output, String> {
    let mut seen = HashSet::new();
    let mut seen_uses = HashSet::new();
    let valid = crate::packages::valid_name;
    if parsed.libraries.len() > MAX_LIBRARIES
        || parsed.loaded_by_listeners.len() > MAX_LISTENER_USES
        || parsed
            .libraries
            .iter()
            .any(|l| !valid(&l.package) || !seen.insert(l.package.clone()))
        || parsed.loaded_by_listeners.iter().any(|u| {
            !valid(&u.package)
                || u.listener.as_deref().is_some_and(|l| !valid(l))
                || u.service.as_deref().is_some_and(|s| !unit_name(s))
                || !matches!(u.class.as_str(), "network" | "loopback")
                || u.sockets.is_empty()
                || u.sockets.len() > MAX_SOCKETS_PER_USE
                || u.sockets.iter().any(|s| !socket_text(s))
                || u.sockets.iter().collect::<HashSet<_>>().len() != u.sockets.len()
                || !seen_uses.insert((u.package.clone(), u.listener.clone(), u.service.clone()))
        })
    {
        return Err("the library scan's result does not fit the contract".into());
    }
    parsed.libraries.sort_by(|a, b| a.package.cmp(&b.package));
    parsed.loaded_by_listeners.sort_by(|a, b| {
        (&a.package, &a.listener, &a.service).cmp(&(&b.package, &b.listener, &b.service))
    });
    Ok(parsed)
}

/// A unit name as the contract allows it: a service or socket unit, or `init.scope`.
fn unit_name(name: &str) -> bool {
    name == "init.scope"
        || ((name.ends_with(".service") || name.ends_with(".socket"))
            && name.len() <= 256
            && !name.starts_with(['-', '.'])
            && name.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(b, b'.' | b'_' | b'@' | b'+' | b'-' | b'\\' | b':')
            }))
}

/// `address:port/protocol`, as [`socket_name`] writes it.
fn socket_text(text: &str) -> bool {
    let Some((address, protocol)) = text.rsplit_once('/') else {
        return false;
    };
    matches!(protocol, "tcp" | "udp") && address.parse::<std::net::SocketAddr>().is_ok()
}

/// The real host for the scan, reading descriptor links directly instead of on a thread per call: the
/// scan reads thousands of them, and its unit's `RuntimeMaxSec=` already bounds a call that hangs.
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
    fn link(&self, path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
        std::fs::read_link(path)
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

/// Most mapped files outside the package-managed prefixes (a user's home, `/tmp`, `/opt`, `/srv`): looked
/// up too, so a package under `/opt` that a process maps is in `libraries` (review of #268, B1), but kept
/// apart from [`MAX_PATHS`], so files a user maps cannot push the package-managed ones out. Over it the
/// scan fails rather than guess.
pub const MAX_OTHER_PATHS: usize = 50_000;
/// Most open file descriptors looked at, across all processes, to find the ones that hold a listening
/// socket.
pub const MAX_DESCRIPTORS: usize = 500_000;
/// Most entries in `loaded_by_listeners`, the contract's limit.
pub const MAX_LISTENER_USES: usize = 20_000;
/// Most sockets named per entry.
pub const MAX_SOCKETS_PER_USE: usize = 4;

/// The host's listening sockets: those of pid 1's network namespace. The scan's own namespace is empty
/// (`PrivateNetwork=yes`), and a process in another namespace (a container) holds sockets these files do
/// not list, so it is not counted as listening: a stated limit.
pub const HOST_SOCKETS: [(&str, bool); 4] = [
    ("/proc/1/net/tcp", false),
    ("/proc/1/net/tcp6", false),
    ("/proc/1/net/udp", true),
    ("/proc/1/net/udp6", true),
];
const MAX_PROC_NET_BYTES: u64 = 32 * 1024 * 1024;

/// Where dpkg-managed code normally lives.
fn package_managed(path: &str) -> bool {
    ["/usr/", "/bin/", "/sbin/", "/lib"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// The process ended while the scan read it.
fn gone(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ESRCH)
}

/// The host's listening TCP and bound UDP sockets, by inode.
fn listening_sockets(ctx: &Ctx) -> Result<HashMap<u64, super::sockets::Socket>, String> {
    let mut found = HashMap::new();
    for (path, udp) in HOST_SOCKETS {
        let bytes = match ctx.read(path, MAX_PROC_NET_BYTES) {
            Ok(bytes) => bytes,
            // IPv6 turned off: no tcp6 or udp6.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && path.ends_with('6') => continue,
            Err(e) => return Err(crate::facts::io_reason(path, &e)),
        };
        for socket in super::sockets::parse(&bytes, udp).map_err(|e| format!("{path}: {e}"))? {
            found.insert(socket.inode, socket);
        }
        if found.len() > super::MAX_SOCKETS {
            return Err(format!(
                "more than {} listening sockets, more than the scan looks at",
                super::MAX_SOCKETS
            ));
        }
    }
    Ok(found)
}

/// The inode of a `socket:[N]` descriptor link.
fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// `address:port/protocol`, IPv6 in brackets.
fn socket_name(socket: &super::sockets::Socket) -> String {
    let protocol = if socket.udp { "udp" } else { "tcp" };
    format!(
        "{}/{protocol}",
        std::net::SocketAddr::new(socket.address, socket.port)
    )
}

/// The `listening` sockets process `pid` holds: empty when none (or it ended meanwhile). `seen` counts
/// the descriptors looked at, across processes.
fn holds<'a>(
    ctx: &Ctx,
    pid: &str,
    listening: &'a HashMap<u64, super::sockets::Socket>,
    seen: &mut usize,
) -> Result<Vec<&'a super::sockets::Socket>, String> {
    let dir = format!("/proc/{pid}/fd");
    let fds = match ctx.list(&dir, MAX_DESCRIPTORS) {
        Ok(fds) => fds,
        Err(e) if gone(&e) => return Ok(Vec::new()),
        Err(e) => return Err(crate::facts::io_reason(&dir, &e)),
    };
    *seen += fds.len();
    if *seen > MAX_DESCRIPTORS {
        return Err(format!(
            "processes hold more than {MAX_DESCRIPTORS} open files, more than the scan looks at"
        ));
    }
    let mut found = Vec::new();
    for fd in fds {
        let path = format!("{dir}/{fd}");
        match ctx.link(&path) {
            Ok(target) => {
                if let Some(socket) = socket_inode(&target).and_then(|i| listening.get(&i)) {
                    found.push(socket);
                }
            }
            // Closed meanwhile, or the process ended.
            Err(e) if gone(&e) => {}
            Err(e) => return Err(crate::facts::io_reason(&path, &e)),
        }
    }
    Ok(found)
}

/// The systemd unit of process `pid`, from its cgroup v2 path (`0::/system.slice/ssh.service`):
/// a service or socket unit in `system.slice`, or `init.scope`; `None` elsewhere or when it ended.
fn unit_of_process(ctx: &Ctx, pid: &str) -> Result<Option<String>, String> {
    let path = format!("/proc/{pid}/cgroup");
    let bytes = match ctx.read(&path, 64 * 1024) {
        Ok(bytes) => bytes,
        Err(e) if gone(&e) => return Ok(None),
        Err(e) => return Err(crate::facts::io_reason(&path, &e)),
    };
    let text = String::from_utf8_lossy(&bytes);
    let Some(cgroup) = text.lines().find_map(|l| l.strip_prefix("0::/")) else {
        return Ok(None);
    };
    Ok(match super::units::unit_of(cgroup.trim_end()) {
        super::units::Owner::Service(unit) => Some(unit),
        super::units::Owner::Systemd(Some(unit)) => Some(unit),
        super::units::Owner::Systemd(None) => Some("init.scope".into()),
        super::units::Owner::Other => None,
    })
}

/// A process that holds a listening socket: whether one is on the network, the sockets, its program,
/// its unit, and what it maps.
struct Listener {
    network: bool,
    /// (on loopback, `address:port/protocol`).
    sockets: Vec<(bool, String)>,
    program: Option<String>,
    service: Option<String>,
    files: Vec<String>,
}

/// The scan itself, on any host, within [`BUDGET`].
pub fn scan(host: &dyn Host) -> Result<Output, String> {
    scan_within(host, BUDGET)
}

/// [`scan`] with another budget (the tests).
pub fn scan_within(host: &dyn Host, budget: Duration) -> Result<Output, String> {
    let ctx = Ctx::new(host, budget);
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
    let sockets = listening_sockets(&ctx)?;
    // Path -> mapped deleted (stale) by any process, and how many of them are package-managed.
    let mut mapped: BTreeMap<String, bool> = BTreeMap::new();
    let (mut managed, mut other) = (0usize, 0usize);
    let mut listeners: Vec<Listener> = Vec::new();
    let mut descriptors = 0usize;
    for pid in &pids {
        let path = format!("/proc/{pid}/maps");
        let bytes = match ctx.read(&path, MAX_MAPS_BYTES) {
            Ok(bytes) => bytes,
            Err(e) if gone(&e) => continue,
            Err(e) => return Err(crate::facts::io_reason(&path, &e)),
        };
        let files = parse_maps(&bytes);
        for (file, deleted) in &files {
            let entry = mapped.entry(file.clone());
            if matches!(entry, std::collections::btree_map::Entry::Vacant(_)) {
                if package_managed(file) {
                    managed += 1;
                } else {
                    other += 1;
                }
            }
            *entry.or_insert(false) |= deleted;
        }
        if managed > MAX_PATHS {
            return Err(format!(
                "processes map more than {MAX_PATHS} files under /usr, /bin, /sbin, and /lib, more than the scan reads"
            ));
        }
        if other > MAX_OTHER_PATHS {
            return Err(format!(
                "processes map more than {MAX_OTHER_PATHS} files elsewhere, more than the scan reads"
            ));
        }
        if sockets.is_empty() {
            continue;
        }
        let held = holds(&ctx, pid, &sockets, &mut descriptors)?;
        if held.is_empty() {
            continue;
        }
        let network = held.iter().any(|s| !s.loopback());
        let exe = format!("/proc/{pid}/exe");
        let program = match ctx.link(&exe) {
            Ok(target) => Some(target.trim_end_matches(" (deleted)").to_owned()),
            // A kernel thread has no program; a process may end meanwhile.
            Err(e) if gone(&e) => None,
            Err(e) => return Err(crate::facts::io_reason(&exe, &e)),
        };
        let service = unit_of_process(&ctx, pid)?;
        listeners.push(Listener {
            network,
            sockets: held
                .iter()
                .map(|s| (s.loopback(), socket_name(s)))
                .collect(),
            program,
            service,
            files: files.into_iter().map(|(file, _)| file).collect(),
        });
    }

    // One pass over dpkg's file lists: every package that lists a mapped file or a listener's program (a
    // diverted or shared file marks each of them, review of #268, S7).
    let mut wanted: HashSet<String> = mapped.keys().cloned().collect();
    wanted.extend(listeners.iter().filter_map(|l| l.program.clone()));
    let lookup = super::owners::lookup(&wanted);
    let mut owners: HashMap<String, BTreeSet<String>> = HashMap::new();
    super::owners::each_list(&ctx, |package, lines| {
        for line in lines {
            if let Some(originals) = lookup.get(line.as_ref()) {
                for original in originals {
                    owners
                        .entry((*original).clone())
                        .or_default()
                        .insert(package.to_owned());
                }
            }
        }
        true
    })?;
    let mut packages: BTreeMap<String, bool> = BTreeMap::new();
    for (file, deleted) in &mapped {
        for package in owners.get(file).into_iter().flatten() {
            *packages.entry(package.clone()).or_insert(false) |= deleted;
        }
    }
    // (package, the listener's package, its unit) -> on the network, and the sockets (network ones
    // first, then by name).
    type Key = (String, Option<String>, Option<String>);
    let mut uses: BTreeMap<Key, (bool, BTreeSet<(bool, String)>)> = BTreeMap::new();
    for listener in &listeners {
        let named = listener
            .program
            .as_ref()
            .and_then(|p| owners.get(p))
            .and_then(|set| set.iter().next().cloned());
        for file in &listener.files {
            for package in owners.get(file).into_iter().flatten() {
                let entry = uses
                    .entry((package.clone(), named.clone(), listener.service.clone()))
                    .or_default();
                entry.0 |= listener.network;
                entry.1.extend(listener.sockets.iter().cloned());
            }
        }
    }
    if packages.len() > MAX_LIBRARIES || uses.len() > MAX_LISTENER_USES {
        return Err(format!(
            "more than {MAX_LIBRARIES} packages to name, more than the contract allows"
        ));
    }
    Ok(Output {
        libraries: packages
            .into_iter()
            .map(|(package, stale)| Library { package, stale })
            .collect(),
        loaded_by_listeners: uses
            .into_iter()
            .map(
                |((package, listener, service), (network, sockets))| ListenerUse {
                    package,
                    listener,
                    service,
                    class: if network { "network" } else { "loopback" }.into(),
                    sockets: sockets
                        .into_iter()
                        .take(MAX_SOCKETS_PER_USE)
                        .map(|(_, name)| name)
                        .collect(),
                },
            )
            .collect(),
    })
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
