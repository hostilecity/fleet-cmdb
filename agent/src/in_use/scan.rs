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
//! The scan ([`main`]) reads at most [`MAX_PROCESSES`] processes' maps, [`MAX_PATHS`] distinct mapped
//! files under the package-managed prefixes (`/usr`, `/bin`, `/sbin`, `/lib*`) and [`MAX_OTHER_PATHS`]
//! elsewhere, maps every one to each package that lists it ([`super::owners`]; a diverted file marks
//! both), and prints the package names with a `stale` flag. Within its 25 s budget, or it fails.
//!
//! **What it can prove (owner decision 2026-11-20).** Python, Perl, Ruby, Node, and Java read their code
//! with `read(2)` rather than mapping it, so a package of such code can be in use with nothing of it in
//! any process's maps. The scan therefore also lists `native`: the packages it can judge, those that ship
//! at least one ELF executable or shared library under the package-managed prefixes, no ELF file outside
//! them (code under `/opt` is not judged), no file with an [`INTERPRETED`] extension, and no script
//! (`#!`) anywhere: not as a file with an execute bit, not as a file named like code, and not as the
//! target of one of its symlinks ([`classify`]). A package with a file the scan could not read or
//! judge is left out. Only a package in `native` and not in `libraries` may be called idle. Nothing else leaves the scan: no paths,
//! no process ids.

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

/// An [`Output`] as the contract allows it: valid package names, each once, at most
/// [`MAX_LIBRARIES`] of each list, sorted. Used on the scan's output and on a kept record alike.
pub fn check_output(mut parsed: Output) -> Result<Output, String> {
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
    fn inspect(&self, path: &std::path::Path) -> std::io::Result<crate::facts::host::Inspect> {
        crate::facts::host::Inspect::of(path)
    }
    fn resolve(&self, path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
        std::fs::canonicalize(path)
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
    ".war", ".beam", ".php", ".lua", ".tcl", ".sh", ".bash",
];

/// Most mapped files outside the package-managed prefixes (a user's home, `/tmp`, `/opt`, `/srv`): looked
/// up too, so a package under `/opt` that a process maps is in `libraries` (review of #268, B1), but kept
/// apart from [`MAX_PATHS`], so files a user maps cannot push the package-managed ones out. Over it the
/// scan fails rather than guess.
pub const MAX_OTHER_PATHS: usize = 50_000;

/// Where dpkg-managed code normally lives: the scan judges native code only there.
fn package_managed(path: &str) -> bool {
    ["/usr/", "/bin/", "/sbin/", "/lib"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// A file a package ships that could be native code by its name: anything in a `bin`, `sbin`, or
/// `libexec` directory, or a shared library (`*.so`, `*.so.*`). Files with an execute bit are looked at
/// wherever they are ([`classify`]).
fn code_candidate(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or("");
    path.contains("/bin/")
        || path.contains("/sbin/")
        || path.contains("/libexec/")
        || name.ends_with(".so")
        || name.contains(".so.")
}

/// Directories of code loaded or run on demand, never while nothing asks for it: PAM modules, NSS,
/// SASL, gconv, PKCS #11, OpenSSL providers and engines, Kerberos, GIO, GDK pixbuf, and GTK modules, and
/// `libnss_*` (owner decision 2026-11-20, re-review of #268, S3). A package with any file here is never
/// native, so never idle. Set-user-ID and set-group-ID programs (`unix_chkpwd`) count too ([`classify`]).
pub const ON_DEMAND: &[&str] = &[
    "/security/",
    "/sasl2/",
    "/gconv/",
    "/pkcs11/",
    "/ossl-modules/",
    "/engines-3/",
    "/engines-1.1/",
    "/krb5/plugins/",
    "/gio/modules/",
    "/gdk-pixbuf-2.0/",
    "/gtk-3.0/modules/",
    "/gtk-4.0/modules/",
];

fn on_demand(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or("");
    name.starts_with("libnss_")
        || ON_DEMAND.iter().any(|dir| path.contains(dir))
        // A package that ships a D-Bus activation file, a systemd timer, or a cron entry (owner
        // decision 2026-11-21, third review S3).
        || path.contains("/dbus-1/system-services/")
        || path.contains("/dbus-1/services/")
        || ((path.contains("/systemd/system/") || path.contains("/systemd/user/"))
            && name.ends_with(".timer"))
        || path.starts_with("/etc/cron.")
        || path == "/etc/crontab"
        || path == "/etc/anacrontab"
}

/// Interpreted code a package ships; its documentation's examples (`/usr/share/doc`) are not code.
fn interpreted(path: &str) -> bool {
    !path.starts_with("/usr/share/doc/") && INTERPRETED.iter().any(|end| path.ends_with(end))
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
    // Path -> mapped deleted (stale) by any process, and how many of them are package-managed.
    let mut mapped: BTreeMap<String, bool> = BTreeMap::new();
    let (mut managed, mut other) = (0usize, 0usize);
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
            let entry = mapped.entry(file.clone());
            if matches!(entry, std::collections::btree_map::Entry::Vacant(_)) {
                if package_managed(&file) {
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
    }

    // One pass over dpkg's file lists: every package that lists a mapped file (a diverted or shared
    // file marks each of them, review of #268, S7), and each package judged as soon as all its lists
    // (one per architecture, read one after another) are read, so only one package's files are held at
    // a time (third review, S1).
    let wanted: HashSet<String> = mapped.keys().cloned().collect();
    let lookup = super::owners::lookup(&wanted);
    // Programs that cron, a systemd timer, or D-Bus activation starts, by each spelling (owner decision
    // 2026-11-21, third review S3): their packages are never native.
    let started: HashSet<String> = super::starters::started_on_demand(&ctx)?
        .iter()
        .flat_map(|path| super::owners::aliases(path))
        .collect();
    let mut owners: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut native = BTreeSet::new();
    let mut group = Group::default();
    let mut failed: Option<String> = None;
    super::owners::each_list(&ctx, |package, lines| {
        if group.package != package {
            if let Err(why) = group.finish(&ctx, budget, &mut native) {
                failed = Some(why);
                return false;
            }
            group = Group {
                package: package.to_owned(),
                ..Group::default()
            };
        }
        for line in lines {
            if let Some(originals) = lookup.get(line.as_ref()) {
                for original in originals {
                    owners
                        .entry((*original).clone())
                        .or_default()
                        .insert(package.to_owned());
                }
            }
            group.add(&line, &started);
        }
        true
    })?;
    if let Some(why) = failed {
        return Err(why);
    }
    group.finish(&ctx, budget, &mut native)?;

    let mut packages: BTreeMap<String, bool> = BTreeMap::new();
    for (file, deleted) in mapped {
        for package in owners.get(&file).into_iter().flatten() {
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

/// One package's files, across the lists of its architectures, while they are read.
#[derive(Default)]
struct Group {
    package: String,
    files: Vec<String>,
    /// Interpreted code, code run on demand, or a line that is not UTF-8: never native.
    excluded: bool,
    candidate: bool,
}

impl Group {
    fn add(&mut self, line: &str, started: &HashSet<String>) {
        if self.excluded {
            return;
        }
        if line.contains('\u{FFFD}')
            || interpreted(line)
            || on_demand(line)
            || started.contains(line)
        {
            self.excluded = true;
            self.files = Vec::new();
            return;
        }
        self.candidate |= code_candidate(line);
        if line.starts_with('/') && line != "/." {
            self.files.push(line.to_owned());
        }
    }

    /// Judges the package once all its lists are read.
    fn finish(
        &mut self,
        ctx: &Ctx,
        budget: Duration,
        native: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        let files = std::mem::take(&mut self.files);
        if !self.package.is_empty()
            && self.candidate
            && !self.excluded
            && classify(ctx, &files, budget)? == Some(true)
        {
            native.insert(std::mem::take(&mut self.package));
        }
        Ok(())
    }
}

/// Whether a package's files are native code only (owner decision 2026-11-20, review of #268):
///
/// - `Some(true)`: at least one ELF file under the package-managed prefixes, and no script;
/// - `Some(false)`: a set-user-ID or set-group-ID file (run on demand, S3); a script (`#!`) anywhere, as a file with an execute bit, a file named like code, or
///   the target of one of its symlinks; an ELF file outside those prefixes (`/opt`, B1); or no ELF file;
/// - `None`: something could not be read or judged (permission denied, an I/O error): not provable.
///
/// Only a missing file, a directory, or a dangling symlink is skipped. `Err` when the scan's budget ran
/// out: the scan then fails rather than report a partial judgement as complete (B2).
fn classify(ctx: &Ctx, files: &[String], limit: Duration) -> Result<Option<bool>, String> {
    use crate::facts::host::Inspect;
    let budget = || {
        format!(
            "the scan ran out of its {} second budget while judging native code",
            limit.as_secs()
        )
    };
    let gone = |e: &std::io::Error| e.kind() == std::io::ErrorKind::NotFound;
    let mut elf = false;
    for file in files {
        let target = match ctx.inspect(file) {
            // A set-user-ID or set-group-ID program (`unix_chkpwd`) runs on demand (S3).
            Ok(Inspect::File(mode)) if mode & 0o6000 != 0 => return Ok(Some(false)),
            Ok(Inspect::File(mode)) => {
                let executable = mode & 0o111 != 0;
                if !(executable && !file.starts_with("/usr/share/doc/")) && !code_candidate(file) {
                    continue;
                }
                file.clone()
            }
            Ok(Inspect::Symlink) => match ctx.resolve(file) {
                Ok(target) => target,
                Err(e) if gone(&e) => continue,
                Err(_) if ctx.out_of_time() => return Err(budget()),
                Err(_) => return Ok(None),
            },
            Ok(Inspect::Directory) => continue,
            Ok(Inspect::Other) => return Ok(None),
            Err(e) if gone(&e) => continue,
            Err(_) if ctx.out_of_time() => return Err(budget()),
            Err(_) => return Ok(None),
        };
        let followed = target != *file;
        match ctx.head(&target, 4) {
            Ok(head) if head.starts_with(b"#!") => return Ok(Some(false)),
            Ok(head) if head == b"\x7fELF" && !package_managed(&target) => return Ok(Some(false)),
            // Judged by the path its list gives, but the maps show where it really is: through a
            // directory symlink outside the /usr merge they differ, and it would never be matched
            // (third review, N2), so such a package cannot be judged.
            Ok(head) if head == b"\x7fELF" && !followed => match ctx.resolve(file) {
                Ok(real) if real == *file || super::owners::aliases(file).contains(&real) => {
                    elf = true;
                }
                Ok(_) => return Ok(Some(false)),
                Err(_) if ctx.out_of_time() => return Err(budget()),
                Err(_) => return Ok(None),
            },
            Ok(_) => {}
            Err(e) if gone(&e) => {}
            // A symlink to a directory, or to something that is not a regular file.
            Err(e) if followed && e.kind() == std::io::ErrorKind::Other => {}
            Err(_) if ctx.out_of_time() => return Err(budget()),
            Err(_) => return Ok(None),
        }
    }
    // Every file was looked at: a budget that ran out after the last one is the next package's
    // first call's error.
    Ok(Some(elf))
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
