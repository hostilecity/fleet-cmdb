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
//! timed out, so a hung `/proc` file or `statvfs` cannot stall the agent. A result is judged by when
//! the read finished, not when it was picked up, so a read that finished late is a timeout even if
//! the collector was busy elsewhere. Per-mount `statvfs` calls start once the mount table has been
//! read, so a whole collection takes at most about twice the limit. Source files must be regular files
//! (procfs files are) and are opened without blocking, so a FIFO or device at a source path is refused
//! at once rather than waited on.
//!
//! An abandoned read cannot be cancelled, so its thread lives until the read returns. A [`Collector`]
//! remembers which sources still have a read in flight and does not start another read of the same
//! source until it returns; that field is reported as still blocked instead. A source stuck forever
//! therefore holds one thread, not one per collection, so the agent keeps one `Collector` for its
//! lifetime.
//!
//! Parsing is separate from reading (the `system`, `disk`, and `network` modules are pure functions
//! over bytes) so it is unit tested with fixture files. Each field is parsed independently: a missing,
//! unreadable, or corrupt source makes that field `null` and adds a [`Warning`] naming the field and the
//! reason, and every other field is still collected. List facts (`disks`, `network_interfaces`) that
//! are readable but partly incomplete keep the entries that could be read and add a warning for the
//! rest.
//!
//! The collector also keeps the report acceptable to the server as a whole (review of #64): available
//! memory larger than total memory is reported as null with a warning, and two disks or interfaces
//! whose names would be the same once the server strips control characters (or once non-UTF-8 bytes
//! are replaced) keep only the first, with a warning. When there are more warnings than the contract
//! allows, every field with a warning keeps at least one.
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

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

pub use sys::{FsStats, HostSystem, IfAddr, System};

/// Time limit for each source read (one file or one syscall).
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest source file read, so a corrupt or hostile file cannot exhaust memory. `/proc/cpuinfo` is
/// about 1.4 KiB per logical CPU, so a host at the contract's 4096-CPU limit needs close to 6 MiB.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

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
    #[cfg(test)]
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
    /// Sources with a read still running, possibly abandoned by an earlier collection.
    in_flight: Arc<Mutex<HashSet<String>>>,
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
            in_flight: Arc::default(),
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
            self.spawn("uname".to_owned(), move || {
                system.machine().map_err(|e| format!("uname: {e}"))
            })
        };
        let cpuinfo = self.read("/proc/cpuinfo");
        let meminfo = self.read("/proc/meminfo");
        let uptime = self.read("/proc/uptime");
        let boot_id = self.read("/proc/sys/kernel/random/boot_id");
        let machine_id = self.read("/etc/machine-id");
        let mounts = self.read("/proc/self/mounts");
        let ifaddrs = {
            let system = Arc::clone(&self.system);
            self.spawn("getifaddrs".to_owned(), move || {
                system
                    .interface_addresses()
                    .map_err(|e| format!("getifaddrs: {e}"))
            })
        };
        let route = self.read("/proc/net/route");
        let ipv6_route = self.read_optional(IPV6_ROUTE);

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
            parse_with(&meminfo, |b| system::parse_meminfo(b, "MemAvailable")).and_then(
                |available| match memory_total_bytes {
                    // The server rejects the whole report for this (review of #64).
                    Some(total) if available > total => Err(format!(
                        "/proc/meminfo: MemAvailable ({available} bytes) exceeds MemTotal ({total} bytes)"
                    )),
                    _ => Ok(available),
                },
            ),
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
        let mut selected = disk::select_real(entries);
        // Reported disks are the first by mount path, so only those are worth a `statvfs`. Capping the
        // calls keeps a host with thousands of mounts from starting thousands of threads.
        selected.sort_by_cached_key(disk::MountEntry::mount_display);
        let candidates = selected.len();
        selected.truncate(disk::MAX_STATVFS);

        let deadline = Instant::now() + self.timeout;
        let pending: Vec<_> = selected
            .into_iter()
            .map(|entry| {
                let system = Arc::clone(&self.system);
                let path = entry.mount_path();
                // Debug keeps non-UTF-8 bytes distinct (`\xFF`), unlike `display`.
                let key = format!("statvfs {path:?}");
                let stats = self.spawn(key, move || {
                    system.statvfs(&path).map_err(|e| e.to_string())
                });
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
        drop_colliding(
            &mut disks,
            |d| &d.mount,
            Field::Disks,
            "mount point",
            warnings,
        );
        if disks.len() > disk::MAX_DISKS || candidates > disk::MAX_STATVFS {
            warnings.push(
                Field::Disks,
                format!(
                    "{candidates} real mounts; reporting the first {} by mount path",
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
        ipv6_route: Result<Option<Vec<u8>>, String>,
        warnings: &mut Warnings,
    ) -> Option<Vec<NetworkInterface>> {
        let addrs = warnings.field(Field::NetworkInterfaces, ifaddrs)?;

        let v4 = route.and_then(|(path, bytes)| at(&path, network::default_route_v4(&bytes)));
        let primary = match v4 {
            Ok(Some(iface)) => Some(iface),
            other => {
                if let Err(e) = other {
                    warnings.push(
                        Field::NetworkInterfaces,
                        format!("primary interface unknown: {e}"),
                    );
                }
                // The IPv6 table is the fallback. Only a missing file is quiet: a host with IPv6
                // disabled has none. Any other failure is reported, since it is now the only way to
                // find the primary interface (review of #64).
                let v6 = ipv6_route.and_then(|bytes| match bytes {
                    None => Ok(None),
                    Some(bytes) => at(IPV6_ROUTE, network::default_route_v6(&bytes)),
                });
                v6.unwrap_or_else(|e| {
                    warnings.push(
                        Field::NetworkInterfaces,
                        format!("primary interface unknown: {e}"),
                    );
                    None
                })
            }
        };

        let (mut interfaces, dropped) = network::interfaces(&addrs, primary.as_deref());
        if let Some(message) = dropped {
            warnings.push(Field::NetworkInterfaces, message);
        }
        drop_colliding(
            &mut interfaces,
            |i| &i.name,
            Field::NetworkInterfaces,
            "interface name",
            warnings,
        );
        // Without this an operator would see no primary interface and no reason for it.
        if let Some(iface) = primary
            && !interfaces.iter().any(|i| i.primary)
        {
            warnings.push(
                Field::NetworkInterfaces,
                format!(
                    "the default route uses {}, which is not reported (down, a container bridge, or no reportable address), so no interface is primary",
                    iface.escape_debug()
                ),
            );
        }
        Some(interfaces)
    }

    /// Starts reading one source file, named by its absolute path on the host.
    fn read(&self, path: &'static str) -> Pending<(String, Vec<u8>)> {
        self.read_first(&[path])
    }

    /// Starts reading a file that may legitimately be absent: a missing file is `Ok(None)`.
    fn read_optional(&self, path: &'static str) -> Pending<Option<Vec<u8>>> {
        let file = self.root.join(path.trim_start_matches('/'));
        self.spawn(path.to_owned(), move || match read_capped(&file) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{path}: {e}")),
        })
    }

    /// Starts reading the first of `paths` that exists.
    fn read_first(&self, paths: &[&'static str]) -> Pending<(String, Vec<u8>)> {
        let root = self.root.clone();
        let key = paths.join(" ");
        let paths = paths.to_vec();
        self.spawn(key, move || {
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

/// The kernel hostname for a heartbeat, read and checked exactly as the inventory's `hostname`, or
/// `None` if it cannot be read (the heartbeat then carries `null`; the credential identifies the host).
/// Read directly rather than through a [`Collector`]: a sysctl read does not block, and the heartbeat
/// loop must not wait for a whole collection.
pub fn hostname() -> Option<String> {
    hostname_under(Path::new("/"))
}

fn hostname_under(root: &Path) -> Option<String> {
    let bytes = read_capped(&root.join("proc/sys/kernel/hostname")).ok()?;
    system::parse_hostname(&bytes).ok()
}

/// Reads a regular file of at most [`MAX_FILE_BYTES`].
///
/// Every source is a regular file (procfs files included), so anything else is refused before it is
/// read. The open itself never waits: `O_NONBLOCK` stops a FIFO with no writer from blocking, and
/// `O_NOCTTY` stops a terminal device at a source path from becoming the controlling terminal of the
/// agent, which runs as root.
fn read_capped(path: &Path) -> io::Result<Vec<u8>> {
    crate::fsx::read_regular(path, MAX_FILE_BYTES, crate::fsx::Symlinks::Follow)
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

const IPV6_ROUTE: &str = "/proc/net/ipv6_route";

impl Collector {
    /// Runs `read` on a new thread, unless a read of the same `source` is still running (for
    /// example abandoned by an earlier collection after a timeout). The thread is detached: if it
    /// hangs, [`Pending::wait`] gives up on it, and `source` stays marked until it returns.
    fn spawn<T: Send + 'static>(
        &self,
        source: String,
        read: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) -> Pending<T> {
        let in_flight = Arc::clone(&self.in_flight);
        if !lock(&in_flight).insert(source.clone()) {
            return Pending {
                receiver: Err(
                    "an earlier read of this source has not returned; not starting another"
                        .to_owned(),
                ),
            };
        }
        let guard = InFlight {
            set: Arc::clone(&in_flight),
            source: source.clone(),
        };
        let (sender, receiver) = mpsc::sync_channel(1);
        let spawned = thread::Builder::new()
            .name("fleet-agent-collect".to_owned())
            .spawn(move || {
                let result = read();
                let finished = Instant::now();
                // Unmark before sending, so the next collection can read this source again.
                drop(guard);
                // The receiver may have given up already; nothing to do then.
                let _ = sender.send((result, finished));
            });
        Pending {
            receiver: spawned.map(|_| receiver).map_err(|e| {
                // The closure, and the guard with it, was dropped: the source is unmarked.
                format!("could not start collector thread: {e}")
            }),
        }
    }
}

/// Marks a source as being read; unmarks it when dropped (also if the read panics).
struct InFlight {
    set: Arc<Mutex<HashSet<String>>>,
    source: String,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        lock(&self.set).remove(&self.source);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a read thread sends: its result and when it finished.
type Finished<T> = (Result<T, String>, Instant);

/// A read running on its own thread.
struct Pending<T> {
    receiver: Result<mpsc::Receiver<Finished<T>>, String>,
}

impl<T> Pending<T> {
    /// The result, or a timeout error if the read did not finish by `deadline`. A result that
    /// finished late but is picked up afterwards is still a timeout (review of #64).
    fn wait(self, deadline: Instant, limit: Duration) -> Result<T, String> {
        let receiver = self.receiver?;
        let timed_out = || Err(format!("read timed out after {}", human(limit)));
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok((_, finished)) if finished > deadline => timed_out(),
            Ok((result, _)) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => timed_out(),
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

    /// At most [`MAX_WARNINGS`], in the order they were raised. When some must go, the first warning
    /// for each field is kept, so a `null` fact never loses its explanation to a run of per-mount
    /// details (review of #64); the remaining slots go to the earliest of the rest.
    fn finish(self) -> Vec<Warning> {
        if self.0.len() <= MAX_WARNINGS {
            return self.0;
        }
        let mut keep = vec![false; self.0.len()];
        let mut fields = Vec::new();
        for (i, warning) in self.0.iter().enumerate() {
            if !fields.contains(&warning.field) {
                fields.push(warning.field);
                keep[i] = true;
            }
        }
        let mut room = MAX_WARNINGS - fields.len();
        for slot in keep.iter_mut().filter(|k| !**k) {
            if room == 0 {
                break;
            }
            *slot = true;
            room -= 1;
        }
        self.0
            .into_iter()
            .zip(keep)
            .filter_map(|(warning, keep)| keep.then_some(warning))
            .collect()
    }
}

/// A name as the server compares it: with the control characters it strips removed (U+0000 to
/// U+001F and U+007F to U+009F, `cmdb/lib/agent_api/inventory_report.rb`).
fn server_key(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(u32::from(*c), 0..=0x1f | 0x7f..=0x9f))
        .collect()
}

/// Keeps the first of any entries whose names the server would see as equal, with a warning for each
/// one dropped; the server rejects a whole report with a duplicate name (review of #64). Names that
/// differed only in non-UTF-8 bytes already look equal here, since both were decoded with U+FFFD.
fn drop_colliding<T>(
    items: &mut Vec<T>,
    name: impl Fn(&T) -> &String,
    field: Field,
    what: &str,
    warnings: &mut Warnings,
) {
    let mut seen = HashSet::new();
    items.retain(|item| {
        let name = name(item);
        if seen.insert(server_key(name)) {
            return true;
        }
        warnings.push(
            field,
            format!(
                "{}: {what} is the same as an earlier one once control characters are removed; not reported",
                name.escape_debug()
            ),
        );
        false
    });
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
pub(crate) mod contract;

#[cfg(test)]
mod tests;
