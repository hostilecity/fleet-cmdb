//! Read-only collectors for host facts (FR-1.3).
//!
//! Gathers system, disk, and network facts for Debian 13 on x86_64 (DEC-01) and classes them as stable
//! or volatile (DEC-07). Collectors only read; they never change the host and never run a command.
//! Phase 2 adds configuration facts and dpkg packages.
//!
//! # How a collection runs
//!
//! [`Collector::collect`] starts every source read at once, each on its own thread: one file (under a
//! root directory, `/` in production) or one syscall through [`System`]. Each read has a time limit
//! ([`READ_TIMEOUT`]); a read that has not finished by then is abandoned and its field reported as
//! timed out, so a hung `/proc` file or `statvfs` cannot stall the agent. Per-mount `statvfs` calls
//! start once the mount table has been read, so a whole collection takes at most about twice the limit.
//!
//! Parsing is separate from reading (the `system`, `disk`, and `network` modules are pure functions
//! over bytes) so it is unit tested with fixture files. Each field is parsed independently: a missing,
//! unreadable, or corrupt source makes that field `null` and adds a [`Warning`] naming the field and the
//! reason, and every other field is still collected. List facts (`disks`, `network_interfaces`) that
//! are readable but partly incomplete keep the entries that could be read and add a warning for the
//! rest.
//!
//! # Sources
//!
//! | Field | Source |
//! |---|---|
//! | `hostname` | `/proc/sys/kernel/hostname` (the kernel hostname, as `hostnamectl` shows it) |
//! | `os` | `/etc/os-release`, falling back to `/usr/lib/os-release`: `ID`, `VERSION_ID`, `PRETTY_NAME` |
//! | `kernel_version` | `/proc/sys/kernel/osrelease` (`uname -r`) |
//! | `architecture` | `uname(2)` machine field; anything but `x86_64` is null plus a warning (DEC-01) |
//! | `cpu_model`, `cpu_cores` | `/proc/cpuinfo`: first `model name`; number of `processor` entries (logical CPUs) |
//! | `memory_total_bytes`, `memory_available_bytes` | `/proc/meminfo` `MemTotal`, `MemAvailable` (as `free` shows them) |
//! | `uptime_seconds` | `/proc/uptime`, whole seconds |
//! | `boot_id` | `/proc/sys/kernel/random/boot_id` |
//! | `machine_id` | `/etc/machine-id` |
//! | `disks` | `/proc/self/mounts` and `statvfs(3)`; see [`disk`] for which mounts count |
//! | `network_interfaces` | `getifaddrs(3)`, `/proc/net/route`, `/proc/net/ipv6_route`; see [`network`] |

mod disk;
mod network;
mod sys;
mod system;

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

pub use sys::{FsStats, HostSystem, IfAddr, System};

/// Time limit for each source read (one file or one syscall).
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest source file read, so a corrupt or hostile file cannot exhaust memory.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Schema limits from `docs/api/schemas/v1/inventory.request.schema.json`.
const MAX_WARNINGS: usize = 64;
const MAX_WARNING_MESSAGE: usize = 512;

/// The facts in an inventory report, named as in the API contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Hostname,
    Os,
    KernelVersion,
    Architecture,
    CpuModel,
    CpuCores,
    MemoryTotalBytes,
    MemoryAvailableBytes,
    UptimeSeconds,
    BootId,
    MachineId,
    Disks,
    NetworkInterfaces,
}

impl Field {
    /// Volatile facts refresh current state only; every other fact is stable and a change to it
    /// triggers an extra report and a new snapshot (FR-1.3, DEC-07). `disks` is stable except for each
    /// disk's `free_bytes`, which is volatile; see [`Inventory::stable`].
    pub fn is_volatile(self) -> bool {
        matches!(self, Field::MemoryAvailableBytes | Field::UptimeSeconds)
    }
}

/// A fact that could not be collected, or a list fact that is incomplete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Warning {
    pub field: Field,
    pub message: String,
}

/// `os` in the report, from `os-release(5)`. A key the file lacks is `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OsRelease {
    pub id: Option<String>,
    pub version_id: Option<String>,
    pub pretty_name: Option<String>,
}

/// One real mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Disk {
    pub mount: String,
    pub filesystem: String,
    pub size_bytes: u64,
    /// Space available to unprivileged users (the `Avail` column of `df`). Volatile.
    pub free_bytes: u64,
}

/// One up, non-loopback interface with its addresses in CIDR notation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkInterface {
    pub name: String,
    pub primary: bool,
    pub addresses: Vec<String>,
}

/// Everything the collectors gathered. Serialises to exactly the fact fields of an inventory report
/// (`docs/api/schemas/v1/inventory.request.schema.json`); the report envelope (`schema_version`,
/// `agent_version`, `report_id`, `collected_at`) is added by the reporter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Inventory {
    pub hostname: Option<String>,
    pub os: Option<OsRelease>,
    pub kernel_version: Option<String>,
    pub architecture: Option<String>,
    pub cpu_model: Option<String>,
    pub cpu_cores: Option<u32>,
    pub memory_total_bytes: Option<u64>,
    pub memory_available_bytes: Option<u64>,
    pub uptime_seconds: Option<u64>,
    pub boot_id: Option<String>,
    pub machine_id: Option<String>,
    pub disks: Option<Vec<Disk>>,
    pub network_interfaces: Option<Vec<NetworkInterface>>,
    pub warnings: Vec<Warning>,
}

/// The stable part of a disk entry: everything but free space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StableDisk {
    pub mount: String,
    pub filesystem: String,
    pub size_bytes: u64,
}

/// The stable facts of an [`Inventory`] (FR-1.3, DEC-07). Two collections with equal stable facts need
/// no extra report. The agent version, also stable, is not a collected fact and is compared by the
/// reporter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StableFacts {
    pub hostname: Option<String>,
    pub os: Option<OsRelease>,
    pub kernel_version: Option<String>,
    pub architecture: Option<String>,
    pub cpu_model: Option<String>,
    pub cpu_cores: Option<u32>,
    pub memory_total_bytes: Option<u64>,
    pub boot_id: Option<String>,
    pub machine_id: Option<String>,
    pub disks: Option<Vec<StableDisk>>,
    pub network_interfaces: Option<Vec<NetworkInterface>>,
}

impl Inventory {
    /// The stable facts, dropping available memory, uptime, and free disk space.
    pub fn stable(&self) -> StableFacts {
        StableFacts {
            hostname: self.hostname.clone(),
            os: self.os.clone(),
            kernel_version: self.kernel_version.clone(),
            architecture: self.architecture.clone(),
            cpu_model: self.cpu_model.clone(),
            cpu_cores: self.cpu_cores,
            memory_total_bytes: self.memory_total_bytes,
            boot_id: self.boot_id.clone(),
            machine_id: self.machine_id.clone(),
            disks: self.disks.as_ref().map(|disks| {
                disks
                    .iter()
                    .map(|d| StableDisk {
                        mount: d.mount.clone(),
                        filesystem: d.filesystem.clone(),
                        size_bytes: d.size_bytes,
                    })
                    .collect()
            }),
            network_interfaces: self.network_interfaces.clone(),
        }
    }
}

/// Collects host facts from a root directory and a [`System`].
pub struct Collector {
    root: PathBuf,
    system: Arc<dyn System>,
    timeout: Duration,
}

impl Default for Collector {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector {
    /// Collects from this host: files under `/` and real syscalls.
    pub fn new() -> Self {
        Self::with(PathBuf::from("/"), Arc::new(HostSystem), READ_TIMEOUT)
    }

    /// Collects with source files read under `root` instead of `/` (tests use a fixture tree), the
    /// given syscall source, and a per-read time limit.
    pub fn with(root: PathBuf, system: Arc<dyn System>, timeout: Duration) -> Self {
        Self {
            root,
            system,
            timeout,
        }
    }

    /// Runs every collector. Never fails: anything unreadable is `null` plus a warning.
    pub fn collect(&self) -> Inventory {
        let start = Instant::now();
        let deadline = start + self.timeout;

        // Start every read before waiting on any of them.
        let hostname = self.read("/proc/sys/kernel/hostname");
        let os_release = self.read_first(&["/etc/os-release", "/usr/lib/os-release"]);
        let osrelease = self.read("/proc/sys/kernel/osrelease");
        let machine = {
            let system = Arc::clone(&self.system);
            spawn(move || system.machine().map_err(|e| format!("uname: {e}")))
        };
        let cpuinfo = self.read("/proc/cpuinfo");
        let meminfo = self.read("/proc/meminfo");
        let uptime = self.read("/proc/uptime");
        let boot_id = self.read("/proc/sys/kernel/random/boot_id");
        let machine_id = self.read("/etc/machine-id");
        let mounts = self.read("/proc/self/mounts");
        let ifaddrs = {
            let system = Arc::clone(&self.system);
            spawn(move || {
                system
                    .interface_addresses()
                    .map_err(|e| format!("getifaddrs: {e}"))
            })
        };
        let route = self.read("/proc/net/route");
        let ipv6_route = self.read("/proc/net/ipv6_route");

        let mut warnings = Warnings::default();
        let limit = self.timeout;

        let hostname = warnings.field(
            Field::Hostname,
            hostname
                .wait(deadline, limit)
                .and_then(|(path, bytes)| at(&path, system::parse_hostname(&bytes))),
        );
        let os = warnings.field(
            Field::Os,
            os_release
                .wait(deadline, limit)
                .and_then(|(path, bytes)| at(&path, system::parse_os_release(&bytes))),
        );
        let kernel_version = warnings.field(
            Field::KernelVersion,
            osrelease
                .wait(deadline, limit)
                .and_then(|(path, bytes)| at(&path, system::parse_kernel_version(&bytes))),
        );
        let architecture = warnings.field(
            Field::Architecture,
            machine
                .wait(deadline, limit)
                .and_then(|m| at("uname", system::parse_architecture(&m))),
        );
        let cpuinfo = cpuinfo.wait(deadline, limit);
        let cpu_model = warnings.field(
            Field::CpuModel,
            parse_with(&cpuinfo, system::parse_cpu_model),
        );
        let cpu_cores = warnings.field(
            Field::CpuCores,
            parse_with(&cpuinfo, system::parse_cpu_cores),
        );
        let meminfo = meminfo.wait(deadline, limit);
        let memory_total_bytes = warnings.field(
            Field::MemoryTotalBytes,
            parse_with(&meminfo, |b| system::parse_meminfo(b, "MemTotal")),
        );
        let memory_available_bytes = warnings.field(
            Field::MemoryAvailableBytes,
            parse_with(&meminfo, |b| system::parse_meminfo(b, "MemAvailable")),
        );
        let uptime_seconds = warnings.field(
            Field::UptimeSeconds,
            uptime
                .wait(deadline, limit)
                .and_then(|(path, bytes)| at(&path, system::parse_uptime(&bytes))),
        );
        let boot_id = warnings.field(
            Field::BootId,
            boot_id
                .wait(deadline, limit)
                .and_then(|(path, bytes)| at(&path, system::parse_boot_id(&bytes))),
        );
        let machine_id = warnings.field(
            Field::MachineId,
            machine_id
                .wait(deadline, limit)
                .and_then(|(path, bytes)| at(&path, system::parse_machine_id(&bytes))),
        );

        let disks = self.collect_disks(mounts.wait(deadline, limit), &mut warnings);
        let network_interfaces = self.collect_network(
            ifaddrs.wait(deadline, limit),
            route.wait(deadline, limit),
            ipv6_route.wait(deadline, limit),
            &mut warnings,
        );

        Inventory {
            hostname,
            os,
            kernel_version,
            architecture,
            cpu_model,
            cpu_cores,
            memory_total_bytes,
            memory_available_bytes,
            uptime_seconds,
            boot_id,
            machine_id,
            disks,
            network_interfaces,
            warnings: warnings.finish(),
        }
    }

    fn collect_disks(
        &self,
        mounts: Result<(String, Vec<u8>), String>,
        warnings: &mut Warnings,
    ) -> Option<Vec<Disk>> {
        let entries = warnings.field(
            Field::Disks,
            mounts.and_then(|(path, bytes)| at(&path, disk::parse_mounts(&bytes))),
        )?;
        let selected = disk::select_real(entries);

        let deadline = Instant::now() + self.timeout;
        let pending: Vec<_> = selected
            .into_iter()
            .map(|entry| {
                let system = Arc::clone(&self.system);
                let path = entry.mount_path();
                let stats = spawn(move || system.statvfs(&path).map_err(|e| e.to_string()));
                (entry, stats)
            })
            .collect();

        let mut disks = Vec::new();
        for (entry, stats) in pending {
            let mount = entry.mount_display();
            match stats.wait(deadline, self.timeout) {
                Ok(stats) => match disk::to_disk(&entry, stats) {
                    Ok(d) => disks.push(d),
                    Err(e) => warnings.push(Field::Disks, format!("{mount}: {e}")),
                },
                Err(e) => warnings.push(Field::Disks, format!("{mount}: statvfs: {e}")),
            }
        }
        disks.sort_by(|a, b| a.mount.cmp(&b.mount));
        if disks.len() > disk::MAX_DISKS {
            warnings.push(
                Field::Disks,
                format!(
                    "{} real mounts; reporting the first {} by mount path",
                    disks.len(),
                    disk::MAX_DISKS
                ),
            );
            disks.truncate(disk::MAX_DISKS);
        }
        Some(disks)
    }

    fn collect_network(
        &self,
        ifaddrs: Result<Vec<IfAddr>, String>,
        route: Result<(String, Vec<u8>), String>,
        ipv6_route: Result<(String, Vec<u8>), String>,
        warnings: &mut Warnings,
    ) -> Option<Vec<NetworkInterface>> {
        let addrs = warnings.field(Field::NetworkInterfaces, ifaddrs)?;

        let v4 = route.and_then(|(path, bytes)| at(&path, network::default_route_v4(&bytes)));
        // A host with IPv6 disabled has no /proc/net/ipv6_route; that is not worth a warning.
        let v6 = ipv6_route
            .ok()
            .and_then(|(_, bytes)| network::default_route_v6(&bytes).ok().flatten());
        let primary = match v4 {
            Ok(Some(iface)) => Some(iface),
            Ok(None) => v6,
            Err(e) => {
                warnings.push(
                    Field::NetworkInterfaces,
                    format!("primary interface unknown: {e}"),
                );
                v6
            }
        };

        let (interfaces, dropped) = network::interfaces(&addrs, primary.as_deref());
        if let Some(message) = dropped {
            warnings.push(Field::NetworkInterfaces, message);
        }
        Some(interfaces)
    }

    /// Starts reading one source file, named by its absolute path on the host.
    fn read(&self, path: &'static str) -> Pending<(String, Vec<u8>)> {
        self.read_first(&[path])
    }

    /// Starts reading the first of `paths` that exists.
    fn read_first(&self, paths: &[&'static str]) -> Pending<(String, Vec<u8>)> {
        let root = self.root.clone();
        let paths = paths.to_vec();
        spawn(move || {
            // When every path fails, report the first (the preferred source).
            let mut first = None;
            for path in &paths {
                match read_capped(&root.join(path.trim_start_matches('/'))) {
                    Ok(bytes) => return Ok(((*path).to_owned(), bytes)),
                    Err(e) => {
                        first.get_or_insert_with(|| format!("{path}: {e}"));
                    }
                }
            }
            Err(first.unwrap_or_else(|| "no source file".to_owned()))
        })
    }
}

fn read_capped(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(io::Error::other(format!(
            "larger than {MAX_FILE_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

/// Prefixes a parse error with the source it came from.
fn at<T>(source: &str, parsed: Result<T, String>) -> Result<T, String> {
    parsed.map_err(|e| format!("{source}: {e}"))
}

/// Parses one field out of a source shared by several fields.
fn parse_with<T>(
    read: &Result<(String, Vec<u8>), String>,
    parse: impl FnOnce(&[u8]) -> Result<T, String>,
) -> Result<T, String> {
    match read {
        Ok((path, bytes)) => at(path, parse(bytes)),
        Err(e) => Err(e.clone()),
    }
}

/// A read running on its own thread.
struct Pending<T> {
    receiver: Result<mpsc::Receiver<Result<T, String>>, String>,
}

/// Runs `read` on a new thread. The thread is detached: if it hangs, [`Pending::wait`] gives up on it.
fn spawn<T: Send + 'static>(
    read: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Pending<T> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let spawned = thread::Builder::new()
        .name("fleet-agent-collect".to_owned())
        .spawn(move || {
            // The receiver may have given up already; nothing to do then.
            let _ = sender.send(read());
        });
    Pending {
        receiver: spawned
            .map(|_| receiver)
            .map_err(|e| format!("could not start collector thread: {e}")),
    }
}

impl<T> Pending<T> {
    /// The result, or a timeout error once `deadline` passes.
    fn wait(self, deadline: Instant, limit: Duration) -> Result<T, String> {
        let receiver = self.receiver?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                Err(format!("read timed out after {}", human(limit)))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err("collector thread ended without a result".to_owned())
            }
        }
    }
}

fn human(d: Duration) -> String {
    if d.subsec_millis() == 0 {
        format!("{}s", d.as_secs())
    } else {
        format!("{}ms", d.as_millis())
    }
}

/// Collection warnings, capped to the contract's limits.
#[derive(Default)]
struct Warnings(Vec<Warning>);

impl Warnings {
    /// The value, or `None` plus a warning.
    fn field<T>(&mut self, field: Field, result: Result<T, String>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(message) => {
                self.push(field, message);
                None
            }
        }
    }

    fn push(&mut self, field: Field, message: String) {
        self.0.push(Warning {
            field,
            message: truncate(message, MAX_WARNING_MESSAGE),
        });
    }

    fn finish(mut self) -> Vec<Warning> {
        self.0.truncate(MAX_WARNINGS);
        self.0
    }
}

/// Cuts `s` to at most `max` characters, marking the cut.
fn truncate(s: String, max: usize) -> String {
    if s.chars().count() <= max {
        return s;
    }
    let mut out: String = s.chars().take(max - 1).collect();
    out.push('…');
    out
}

#[cfg(test)]
#[path = "../../tests/support/contract.rs"]
mod contract;

#[cfg(test)]
mod tests;
