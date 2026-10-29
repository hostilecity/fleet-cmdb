//! Whole-collection tests against a fake root directory built from the Debian 13 fixtures in
//! `tests/fixtures/collect/debian13`, with a fake [`System`] for the syscalls.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::*;

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/collect/debian13")
}

/// A scratch copy of the fixture tree that a test may break, removed on drop.
struct FakeRoot(PathBuf);

impl FakeRoot {
    fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fleet-agent-collect-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&dir);
        copy_tree(&fixture_root(), &dir).expect("copy fixtures");
        Self(dir)
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel.trim_start_matches('/'))
    }

    fn remove(&self, rel: &str) {
        fs::remove_file(self.path(rel)).expect("remove fixture file");
    }

    fn write(&self, rel: &str, contents: &[u8]) {
        let path = self.path(rel);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(path, contents).expect("write fixture file");
    }
}

impl Drop for FakeRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

/// Syscall results for the fixture VM.
struct FakeSystem {
    machine: Result<&'static str, io::ErrorKind>,
    statvfs: HashMap<PathBuf, FsStats>,
    addrs: Result<Vec<IfAddr>, io::ErrorKind>,
    /// Sleep this long in `machine` to simulate a hung syscall.
    hang: Option<Duration>,
}

impl FakeSystem {
    fn new() -> Self {
        let stats = |gib: u64, free_gib: u64| FsStats {
            fragment_size: 4096,
            blocks: gib * 262_144,
            blocks_available: free_gib * 262_144,
        };
        let addr = |name: &str, address: &str, prefix_len: u8, up: bool, loopback: bool| IfAddr {
            name: name.to_owned(),
            up,
            loopback,
            address: address.parse().expect("address"),
            prefix_len,
        };
        Self {
            machine: Ok("x86_64"),
            statvfs: HashMap::from([
                (PathBuf::from("/"), stats(32, 20)),
                (PathBuf::from("/boot/efi"), stats(1, 1)),
                (PathBuf::from("/srv/media files"), stats(1024, 512)),
                (PathBuf::from("/mnt/back\\slash\ttab"), stats(8, 8)),
                (PathBuf::from("/export/media"), stats(1024, 512)),
            ]),
            addrs: Ok(vec![
                addr("lo", "127.0.0.1", 8, true, true),
                addr("lo", "::1", 128, true, true),
                addr("ens18", "192.0.2.10", 24, true, false),
                addr("ens18", "2001:db8::10", 64, true, false),
                addr("ens18", "fe80::be24:11ff:fe00:1", 64, true, false),
                addr("ens19", "198.51.100.10", 24, true, false),
                addr("ens20", "198.51.100.20", 24, false, false),
                addr("docker0", "203.0.113.1", 24, true, false),
                addr("br-0123456789ab", "203.0.113.129", 25, true, false),
                addr("veth1a2b3c4", "fe80::1", 64, true, false),
            ]),
            hang: None,
        }
    }
}

impl System for FakeSystem {
    fn machine(&self) -> io::Result<String> {
        if let Some(hang) = self.hang {
            std::thread::sleep(hang);
        }
        self.machine
            .map(str::to_owned)
            .map_err(|kind| io::Error::new(kind, "fake failure"))
    }

    fn statvfs(&self, path: &Path) -> io::Result<FsStats> {
        self.statvfs
            .get(path)
            .copied()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn interface_addresses(&self) -> io::Result<Vec<IfAddr>> {
        self.addrs
            .clone()
            .map_err(|kind| io::Error::new(kind, "fake failure"))
    }
}

fn collect_from(root: &Path, system: FakeSystem) -> Inventory {
    Collector::with(root.to_owned(), Arc::new(system), Duration::from_secs(5)).collect()
}

fn expected() -> Inventory {
    let gib = 1024 * 1024 * 1024;
    let disk = |mount: &str, filesystem: &str, size: u64, free: u64| Disk {
        mount: mount.to_owned(),
        filesystem: filesystem.to_owned(),
        size_bytes: size * gib,
        free_bytes: free * gib,
    };
    Inventory {
        hostname: Some("vm-01.example.lan".to_owned()),
        os: Some(OsRelease {
            id: Some("debian".to_owned()),
            version_id: Some("13".to_owned()),
            pretty_name: Some("Debian GNU/Linux 13 (trixie)".to_owned()),
        }),
        kernel_version: Some("6.12.48+deb13-amd64".to_owned()),
        architecture: Some("x86_64".to_owned()),
        cpu_model: Some("Example Virtual CPU @ 2.40GHz".to_owned()),
        cpu_cores: Some(4),
        memory_total_bytes: Some(8_131_244 * 1024),
        memory_available_bytes: Some(6_291_456 * 1024),
        uptime_seconds: Some(86_400),
        boot_id: Some("00000000-0000-4000-8000-0000000000b1".to_owned()),
        machine_id: Some("0123456789abcdef0123456789abcdef".to_owned()),
        disks: Some(vec![
            disk("/", "ext4", 32, 20),
            disk("/boot/efi", "vfat", 1, 1),
            disk("/mnt/back\\slash\ttab", "ext4", 8, 8),
            disk("/srv/media files", "xfs", 1024, 512),
        ]),
        network_interfaces: Some(vec![
            NetworkInterface {
                name: "ens18".to_owned(),
                primary: true,
                addresses: vec!["192.0.2.10/24".to_owned(), "2001:db8::10/64".to_owned()],
            },
            NetworkInterface {
                name: "ens19".to_owned(),
                primary: false,
                addresses: vec!["198.51.100.10/24".to_owned()],
            },
        ]),
        warnings: vec![],
    }
}

/// Adds placeholder report envelope fields so a collection can be checked against the full contract.
fn as_report(inventory: &Inventory) -> serde_json::Value {
    let mut value = serde_json::to_value(inventory).expect("serialise");
    let object = value.as_object_mut().expect("object");
    object.insert("schema_version".to_owned(), 1.into());
    object.insert("agent_version".to_owned(), "0.1.0".into());
    object.insert(
        "report_id".to_owned(),
        "00000000-0000-4000-8000-000000000001".into(),
    );
    object.insert("collected_at".to_owned(), "2026-01-01T12:00:00Z".into());
    value
}

fn warning_for(inventory: &Inventory, field: Field) -> Option<&str> {
    inventory
        .warnings
        .iter()
        .find(|w| w.field == field)
        .map(|w| w.message.as_str())
}

#[test]
fn collects_every_fact_from_the_debian_13_fixtures() {
    assert_eq!(collect_from(&fixture_root(), FakeSystem::new()), expected());
}

#[test]
fn serialises_to_exactly_the_contract_fact_fields() {
    let value = serde_json::to_value(expected()).expect("serialise");
    let mut keys: Vec<&str> = value
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    let schema = contract::schema("v1", "inventory.request");
    let envelope = [
        "agent_version",
        "collected_at",
        "report_id",
        "schema_version",
    ];
    let mut required: Vec<&str> = schema["required"]
        .as_array()
        .expect("required")
        .iter()
        .map(|v| v.as_str().expect("name"))
        .filter(|name| !envelope.contains(name))
        .collect();
    required.sort_unstable();
    assert_eq!(keys, required);
}

#[test]
fn collected_snapshot_conforms_to_the_inventory_contract() {
    let inventory = collect_from(&fixture_root(), FakeSystem::new());
    contract::assert_conforms("v1", "inventory.request", &as_report(&inventory));
}

#[test]
fn degraded_snapshot_conforms_to_the_inventory_contract() {
    let root = FakeRoot::new();
    for rel in [
        "/proc/sys/kernel/hostname",
        "/etc/os-release",
        "/proc/meminfo",
        "/proc/self/mounts",
    ] {
        root.remove(rel);
    }
    let mut system = FakeSystem::new();
    system.machine = Ok("aarch64");
    system.addrs = Err(io::ErrorKind::PermissionDenied);
    let inventory = collect_from(&root.0, system);
    assert_eq!(inventory.warnings.len(), 7, "{:#?}", inventory.warnings);
    contract::assert_conforms("v1", "inventory.request", &as_report(&inventory));
}

/// Source file, the fields it feeds.
const SOURCES: &[(&str, &[Field])] = &[
    ("/proc/sys/kernel/hostname", &[Field::Hostname]),
    ("/etc/os-release", &[Field::Os]),
    ("/proc/sys/kernel/osrelease", &[Field::KernelVersion]),
    ("/proc/cpuinfo", &[Field::CpuModel, Field::CpuCores]),
    (
        "/proc/meminfo",
        &[Field::MemoryTotalBytes, Field::MemoryAvailableBytes],
    ),
    ("/proc/uptime", &[Field::UptimeSeconds]),
    ("/proc/sys/kernel/random/boot_id", &[Field::BootId]),
    ("/etc/machine-id", &[Field::MachineId]),
    ("/proc/self/mounts", &[Field::Disks]),
];

/// The inventory as JSON with the given fields set to null, for comparing the rest.
fn nulled(inventory: &Inventory, fields: &[Field]) -> serde_json::Value {
    let mut value = serde_json::to_value(inventory).expect("serialise");
    let object = value.as_object_mut().expect("object");
    object.remove("warnings");
    for field in fields {
        let name = serde_json::to_value(field).expect("field name");
        object.insert(
            name.as_str().expect("str").to_owned(),
            serde_json::Value::Null,
        );
    }
    value
}

fn assert_only_these_fields_degraded(inventory: &Inventory, source: &str, fields: &[Field]) {
    for field in fields {
        let message = warning_for(inventory, *field)
            .unwrap_or_else(|| panic!("{source}: no warning for {field:?}"));
        assert!(
            message.starts_with(source),
            "{source}: warning for {field:?} does not name the source: {message}"
        );
    }
    assert_eq!(
        inventory.warnings.len(),
        fields.len(),
        "{source}: {:#?}",
        inventory.warnings
    );
    assert_eq!(
        nulled(inventory, fields),
        nulled(&expected(), fields),
        "{source}: other fields changed"
    );
}

#[test]
fn a_missing_source_file_yields_null_plus_a_warning_and_the_rest_intact() {
    for (source, fields) in SOURCES {
        let root = FakeRoot::new();
        root.remove(source);
        let inventory = collect_from(&root.0, FakeSystem::new());
        assert_only_these_fields_degraded(&inventory, source, fields);
        let message = warning_for(&inventory, fields[0]).expect("warning");
        assert!(message.contains("No such file"), "{message}");
    }
}

#[test]
fn a_corrupt_source_file_yields_null_plus_a_warning_and_the_rest_intact() {
    for (source, fields) in SOURCES {
        for garbage in [&b"\xff\xfe\x00\x01"[..], b"", b"\n\n\n"] {
            let root = FakeRoot::new();
            root.write(source, garbage);
            let inventory = collect_from(&root.0, FakeSystem::new());
            assert_only_these_fields_degraded(&inventory, source, fields);
        }
    }
}

#[test]
fn os_release_falls_back_to_usr_lib() {
    let root = FakeRoot::new();
    let contents = fs::read(root.path("/etc/os-release")).expect("read");
    root.remove("/etc/os-release");
    root.write("/usr/lib/os-release", &contents);
    assert_eq!(collect_from(&root.0, FakeSystem::new()), expected());
}

#[test]
fn a_failed_syscall_yields_null_plus_a_warning() {
    let mut system = FakeSystem::new();
    system.machine = Err(io::ErrorKind::PermissionDenied);
    system.addrs = Err(io::ErrorKind::PermissionDenied);
    let inventory = collect_from(&fixture_root(), system);
    assert_eq!(inventory.architecture, None);
    assert_eq!(inventory.network_interfaces, None);
    assert!(
        warning_for(&inventory, Field::Architecture)
            .expect("arch")
            .starts_with("uname")
    );
    assert!(
        warning_for(&inventory, Field::NetworkInterfaces)
            .expect("net")
            .starts_with("getifaddrs")
    );
    assert_eq!(inventory.warnings.len(), 2);
    assert_eq!(inventory.hostname, expected().hostname);
    assert_eq!(inventory.disks, expected().disks);
}

#[test]
fn a_non_x86_64_machine_is_null_plus_a_warning() {
    let mut system = FakeSystem::new();
    system.machine = Ok("aarch64");
    let inventory = collect_from(&fixture_root(), system);
    assert_eq!(inventory.architecture, None);
    assert!(
        warning_for(&inventory, Field::Architecture)
            .expect("warning")
            .contains("DEC-01")
    );
}

#[test]
fn a_failed_statvfs_drops_that_mount_with_a_warning() {
    let mut system = FakeSystem::new();
    system.statvfs.remove(Path::new("/boot/efi"));
    let inventory = collect_from(&fixture_root(), system);
    let mounts: Vec<&str> = inventory
        .disks
        .as_ref()
        .expect("disks")
        .iter()
        .map(|d| d.mount.as_str())
        .collect();
    assert_eq!(mounts, ["/", "/mnt/back\\slash\ttab", "/srv/media files"]);
    assert!(
        warning_for(&inventory, Field::Disks)
            .expect("warning")
            .starts_with("/boot/efi: statvfs")
    );
}

#[test]
fn without_a_routing_table_no_interface_is_primary() {
    let root = FakeRoot::new();
    root.remove("/proc/net/route");
    root.remove("/proc/net/ipv6_route");
    let inventory = collect_from(&root.0, FakeSystem::new());
    let interfaces = inventory.network_interfaces.as_ref().expect("interfaces");
    assert_eq!(interfaces.len(), 2);
    assert!(interfaces.iter().all(|i| !i.primary));
    assert!(
        warning_for(&inventory, Field::NetworkInterfaces)
            .expect("warning")
            .contains("/proc/net/route")
    );
}

#[test]
fn the_ipv6_default_route_marks_primary_when_there_is_no_ipv4_one() {
    let root = FakeRoot::new();
    root.write(
        "/proc/net/route",
        b"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n",
    );
    let inventory = collect_from(&root.0, FakeSystem::new());
    assert_eq!(inventory.network_interfaces, expected().network_interfaces);
    assert!(inventory.warnings.is_empty());
}

#[test]
fn a_hung_syscall_times_out_and_the_rest_is_collected() {
    let mut system = FakeSystem::new();
    system.hang = Some(Duration::from_secs(30));
    let started = Instant::now();
    let inventory =
        Collector::with(fixture_root(), Arc::new(system), Duration::from_millis(200)).collect();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(inventory.architecture, None);
    assert_eq!(
        warning_for(&inventory, Field::Architecture),
        Some("read timed out after 200ms")
    );
    assert_eq!(inventory.hostname, expected().hostname);
    assert_eq!(inventory.disks, expected().disks);
}

#[test]
fn a_hung_file_read_times_out_and_the_rest_is_collected() {
    let root = FakeRoot::new();
    root.remove("/etc/machine-id");
    // Opening a FIFO with no writer blocks, like a hung read.
    let fifo = std::ffi::CString::new(
        root.path("/etc/machine-id")
            .into_os_string()
            .into_encoded_bytes(),
    )
    .expect("path");
    // SAFETY: `fifo` is a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let started = Instant::now();
    let inventory = Collector::with(
        root.0.clone(),
        Arc::new(FakeSystem::new()),
        Duration::from_millis(200),
    )
    .collect();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(inventory.machine_id, None);
    assert_eq!(
        warning_for(&inventory, Field::MachineId),
        Some("read timed out after 200ms")
    );
    assert_eq!(
        nulled(&inventory, &[Field::MachineId]),
        nulled(&expected(), &[Field::MachineId])
    );
    // Unblock the abandoned reader so its thread ends. Non-blocking, so this cannot hang the test.
    let _ = fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(root.path("/etc/machine-id"));
}

#[test]
fn stable_facts_ignore_volatile_changes() {
    let base = expected();
    let mut volatile = base.clone();
    volatile.memory_available_bytes = Some(1);
    volatile.uptime_seconds = Some(2);
    volatile.disks.as_mut().expect("disks")[0].free_bytes = 3;
    assert_eq!(base.stable(), volatile.stable());

    let mut stable = base.clone();
    stable.disks.as_mut().expect("disks")[0].size_bytes += 1;
    assert_ne!(base.stable(), stable.stable());
    let mut stable = base.clone();
    stable.boot_id = Some("00000000-0000-4000-8000-0000000000b2".to_owned());
    assert_ne!(base.stable(), stable.stable());

    assert!(Field::UptimeSeconds.is_volatile());
    assert!(Field::MemoryAvailableBytes.is_volatile());
    assert!(!Field::BootId.is_volatile());
}

#[test]
fn warnings_are_capped_to_the_contract() {
    let mut warnings = Warnings::default();
    for _ in 0..70 {
        warnings.push(Field::Disks, "é".repeat(600));
    }
    let warnings = warnings.finish();
    assert_eq!(warnings.len(), MAX_WARNINGS);
    assert_eq!(warnings[0].message.chars().count(), MAX_WARNING_MESSAGE);
}

/// Sanity check against the machine running the tests (not a fixture). Prints the collection so it can
/// be compared with `hostnamectl`, `free -b`, `df -B1`, and `ip route`:
/// `cargo test collects_from_this_host -- --ignored --nocapture`.
#[test]
#[ignore = "reads the real host; run by hand"]
fn collects_from_this_host() {
    let inventory = Collector::new().collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&inventory).expect("serialise")
    );
    contract::assert_conforms("v1", "inventory.request", &as_report(&inventory));
}
