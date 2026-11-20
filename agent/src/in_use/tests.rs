use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Mutex;

use super::*;
use crate::collect::contract;
use crate::facts::host::{RunError, SocketCgroup, Stat};

/// A host with fixture files, canned command output (by the command's first argument), sockets, and
/// cgroup directories. It records every call.
#[derive(Default)]
struct TestHost {
    files: HashMap<String, Vec<u8>>,
    dirs: HashMap<String, Vec<String>>,
    commands: HashMap<String, Result<Vec<u8>, RunError>>,
    sockets: Option<Vec<SocketCgroup>>,
    cgroups: Option<Vec<(u64, String)>>,
    /// `systemctl show` answers from this, one block per unit asked about, when no output is canned.
    exec: HashMap<String, String>,
    /// Paths whose reads are refused (permission denied).
    denied: std::collections::HashSet<String>,
    /// Files with an execute bit.
    executables: std::collections::HashSet<String>,
    /// Symlinks: path -> target (absolute).
    symlinks: HashMap<String, String>,
    log: Mutex<Vec<String>>,
}

impl TestHost {
    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
    fn file(mut self, path: &str, text: &str) -> Self {
        self.files.insert(path.to_owned(), text.as_bytes().to_vec());
        self
    }
    fn command(mut self, first: &str, output: Result<&str, RunError>) -> Self {
        self.commands
            .insert(first.to_owned(), output.map(|t| t.as_bytes().to_vec()));
        self
    }
}

impl Host for TestHost {
    fn stat(&self, _: &Path) -> io::Result<Stat> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn read(&self, path: &Path, max: u64) -> io::Result<Vec<u8>> {
        let path = path.to_string_lossy().into_owned();
        self.log.lock().unwrap().push(format!("read {path}"));
        if self.denied.contains(&path) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let bytes = self
            .files
            .get(&path)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        if bytes.len() as u64 > max {
            return Err(io::Error::other("too large"));
        }
        Ok(bytes)
    }
    fn list(&self, dir: &Path, max: usize) -> io::Result<Vec<String>> {
        let dir = dir.to_string_lossy().into_owned();
        self.log.lock().unwrap().push(format!("list {dir}"));
        let names = self
            .dirs
            .get(&dir)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        if names.len() > max {
            return Err(io::Error::other("too many"));
        }
        Ok(names)
    }
    fn run(&self, command: &Command) -> Result<Vec<u8>, RunError> {
        self.log
            .lock()
            .unwrap()
            .push(format!("run {}", command.line()));
        let first = command.args.first().cloned().unwrap_or_default();
        if first == "show" && !self.commands.contains_key("show") {
            let dash = command.args.iter().position(|a| a == "--").unwrap();
            let blocks: Vec<String> = command.args[dash + 1..]
                .iter()
                .map(|unit| match self.exec.get(unit) {
                    Some(path) => format!(
                        "ExecStart={{ path={path} ; argv[]={path} --secret-flag=1 ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}\nId={unit}\n"
                    ),
                    None => format!("Id={unit}\n"),
                })
                .collect();
            return Ok(blocks.join("\n").into_bytes());
        }
        self.commands
            .get(&first)
            .cloned()
            .unwrap_or(Err(RunError::NotInstalled(first)))
    }
    fn inspect(&self, path: &Path) -> io::Result<crate::facts::host::Inspect> {
        use crate::facts::host::Inspect;
        let path = path.to_string_lossy().into_owned();
        if self.denied.contains(&path) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if self.symlinks.contains_key(&path) {
            return Ok(Inspect::Symlink);
        }
        if self.files.contains_key(&path) {
            return Ok(Inspect::File(self.executables.contains(&path)));
        }
        if self
            .files
            .keys()
            .any(|f| f.starts_with(&format!("{path}/")))
        {
            return Ok(Inspect::Directory);
        }
        Err(io::ErrorKind::NotFound.into())
    }
    fn resolve(&self, path: &Path) -> io::Result<std::path::PathBuf> {
        let mut path = path.to_string_lossy().into_owned();
        for _ in 0..8 {
            match self.symlinks.get(&path) {
                Some(target) => path = target.clone(),
                None => break,
            }
        }
        if self.files.contains_key(&path)
            || self
                .files
                .keys()
                .any(|f| f.starts_with(&format!("{path}/")))
        {
            Ok(path.into())
        } else {
            Err(io::ErrorKind::NotFound.into())
        }
    }
    fn socket_cgroups(&self, max: usize) -> io::Result<Vec<SocketCgroup>> {
        let sockets = self
            .sockets
            .clone()
            .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
        if sockets.len() > max {
            return Err(io::Error::other("too many"));
        }
        Ok(sockets)
    }
    /// Only `system.slice` and `init.scope` are walked: anything else is a test failure.
    fn directories(&self, root: &Path, _: usize) -> io::Result<Vec<(u64, String)>> {
        let root = root.to_string_lossy().into_owned();
        self.log.lock().unwrap().push(format!("walk {root}"));
        let top = root
            .strip_prefix("/sys/fs/cgroup/")
            .expect("under the cgroup root");
        assert!(["system.slice", "init.scope"].contains(&top), "{top}");
        let all = self
            .cgroups
            .clone()
            .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
        let found: Vec<(u64, String)> = all
            .into_iter()
            .filter_map(|(id, path)| {
                if path == top {
                    Some((id, String::new()))
                } else {
                    path.strip_prefix(&format!("{top}/"))
                        .map(|rest| (id, rest.to_owned()))
                }
            })
            .collect();
        if found.is_empty() {
            return Err(io::ErrorKind::NotFound.into());
        }
        Ok(found)
    }
}

const TCP_HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

/// sshd on 0.0.0.0:22 and [::]:22, smbd on 192.0.2.10:445, a local service on 127.0.0.1:8080, a
/// container on 0.0.0.0:5432, cups (socket-activated) on 127.0.0.1:631, an established connection
/// (not listening), and a tool with no package on 127.0.0.1:9000.
fn tcp() -> String {
    format!(
        "{TCP_HEADER}\
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0 100 0 0 10 0\n\
   1: 0A0200C0:01BD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 0 100 0 0 10 0\n\
   2: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000   108        0 1003 1 0 100 0 0 10 0\n\
   3: 00000000:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 1004 1 0 100 0 0 10 0\n\
   4: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1005 1 0 100 0 0 10 0\n\
   5: 0A0200C0:0016 0B0200C0:D431 01 00000000:00000000 02:00000000 00000000     0        0 1006 2 0 20 4 30 10 -1\n\
   6: 0100007F:2328 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1007 1 0 100 0 0 10 0\n"
    )
}

fn tcp6() -> String {
    format!(
        "{TCP_HEADER}\
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1 0 100 0 0 10 0\n"
    )
}

/// systemd-resolved on 127.0.0.53:53 (bound UDP), a connected UDP client (not counted), and nothing
/// on IPv6.
fn udp() -> String {
    format!(
        "{TCP_HEADER}\
  10: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   991        0 3001 2 0 0\n\
  11: 0A0200C0:A1B2 0B0200C0:0035 01 00000000:00000000 00:00000000 00000000     0        0 3002 2 0 0\n"
    )
}

const RUNNING: &str = "\
cron.service loaded active running Regular background program processing daemon
local-app.service loaded active running A local app
smbd.service loaded active running Samba SMB Daemon
ssh.service loaded active running OpenBSD Secure Shell server
systemd-resolved.service loaded active running Network Name Resolution
tool.service loaded active running A tool from /opt
";

const EXEC: [(&str, &str); 7] = [
    ("cron.service", "/usr/sbin/cron"),
    ("cups.service", "/usr/sbin/cupsd"),
    ("local-app.service", "/usr/bin/local-app"),
    ("smbd.service", "/usr/sbin/smbd"),
    ("ssh.service", "/usr/sbin/sshd"),
    (
        "systemd-resolved.service",
        "/usr/lib/systemd/systemd-resolved",
    ),
    ("tool.service", "/opt/tool/bin/tool"),
];

const LIST_SOCKETS: &str = "\
/run/cups/cups.sock          Stream    cups.socket          cups.service
127.0.0.1:631                Stream    cups.socket          cups.service
127.0.0.1:631                Datagram  cupsudp.socket       cups-browsed.service
/run/dbus/system_bus_socket  Stream    dbus.socket          dbus.service
";

fn debian_host() -> TestHost {
    let mut host = TestHost::default()
        .file("/proc/net/tcp", &tcp())
        .file("/proc/net/tcp6", &tcp6())
        .file("/proc/net/udp", &udp())
        .file("/proc/net/udp6", TCP_HEADER)
        .file(
            "/var/lib/dpkg/info/cron.list",
            "/.\n/usr\n/usr/sbin\n/usr/sbin/cron\n",
        )
        .file("/var/lib/dpkg/info/cups-daemon.list", "/usr/sbin/cupsd\n")
        .file("/var/lib/dpkg/info/local-app.list", "/usr/bin/local-app\n")
        .file(
            "/var/lib/dpkg/info/samba.list",
            "/usr/sbin/smbd\n/usr/sbin/nmbd\n",
        )
        // Before the /usr merge reached it: listed by its old path.
        .file(
            "/var/lib/dpkg/info/openssh-server.list",
            "/sbin/sshd-not\n/usr/sbin/sshd\n",
        )
        .file(
            "/var/lib/dpkg/info/systemd-resolved:amd64.list",
            "/lib/systemd/systemd-resolved\n",
        )
        .command("list-units", Ok(RUNNING))
        .command("list-sockets", Ok(LIST_SOCKETS));
    host.exec = EXEC
        .iter()
        .map(|(unit, path)| ((*unit).to_owned(), (*path).to_owned()))
        .collect();
    host.dirs.insert(
        "/var/lib/dpkg/info".into(),
        [
            "cron.list",
            "cron.md5sums",
            "cups-daemon.list",
            "local-app.list",
            "openssh-server.list",
            "samba.list",
            "systemd-resolved:amd64.list",
        ]
        .map(String::from)
        .to_vec(),
    );
    host.sockets = Some(
        [
            (1001, 11),
            (2001, 11),
            (1002, 12),
            (1003, 13),
            (1004, 14),
            (1005, 2),
            (1007, 17),
            (3001, 15),
        ]
        .map(|(inode, cgroup)| SocketCgroup { inode, cgroup })
        .to_vec(),
    );
    host.cgroups = Some(
        [
            (1, ""),
            (2, "init.scope"),
            (10, "system.slice"),
            (11, "system.slice/ssh.service"),
            (12, "system.slice/smbd.service"),
            (13, "system.slice/system-local.slice/local-app.service"),
            (14, "system.slice/docker-0123abcd.scope"),
            (15, "system.slice/systemd-resolved.service"),
            (17, "system.slice/tool.service/worker"),
        ]
        .map(|(id, path)| (id, path.to_owned()))
        .to_vec(),
    );
    // Socket activation: cups' listener (1005) is held by systemd (init.scope).
    host
}

fn listening(entries: &[(&str, &'static str)]) -> Vec<Listening> {
    entries
        .iter()
        .map(|(package, class)| Listening {
            package: (*package).to_owned(),
            class,
        })
        .collect()
}

#[test]
fn listening_services_are_named_by_package_and_class() {
    let host = debian_host();
    let found = collect(&host, &Scan::Off, &mut scan::Memo::default(), None);
    assert!(found.warnings.is_empty(), "{:?}", found.warnings);
    let in_use = found.in_use.expect("in use");
    assert_eq!(
        in_use.listening,
        listening(&[
            ("cups-daemon", "loopback"),
            ("local-app", "loopback"),
            ("openssh-server", "network"),
            ("samba", "network"),
            ("systemd-resolved", "loopback"),
        ])
    );
    assert_eq!(
        in_use.services,
        [
            "cron",
            "local-app",
            "openssh-server",
            "samba",
            "systemd-resolved"
        ]
    );
    // The container's socket and the tool no package owns: counted, not named.
    assert_eq!(
        in_use.unnamed_listeners,
        Unnamed {
            network: 1,
            loopback: 1
        }
    );
    assert_eq!(in_use.library_scan, "off");
    assert_eq!(in_use.libraries, None);
    assert!(!in_use.complete);
}

#[test]
fn the_report_has_no_process_id_command_line_address_or_port() {
    let host = debian_host();
    let found = collect(&host, &Scan::Off, &mut scan::Memo::default(), None);
    let text = serde_json::to_string(&found.in_use).unwrap();
    for forbidden in [
        "192.0.2", "127.0.0", "0.0.0.0", ":22", "445", "8080", "631", "secret", "/usr/", "argv",
        "pid", "uid", "docker",
    ] {
        assert!(!text.contains(forbidden), "{forbidden} in {text}");
    }
}

#[test]
fn in_use_conforms_to_the_package_report_contract() {
    let host = debian_host();
    let found = collect(&host, &Scan::Off, &mut scan::Memo::default(), None);
    let report = report_with(&found);
    contract::assert_conforms("v1", "packages.request", &report);
    assert_eq!(report["in_use"]["listening"][2]["class"], "network");
    // Not collected: left out, as before.
    let plain = decode(&crate::report::packages::encode(
        "00000000-0000-4000-8000-000000000001",
        "2026-01-01T12:00:00Z",
        &listing(),
    ));
    assert!(plain.get("in_use").is_none());
    // Unreadable: null, with a warning.
    let failed = Collected {
        in_use: None,
        warnings: vec!["the sockets' cgroups cannot be read".into()],
    };
    let report = report_with(&failed);
    contract::assert_conforms("v1", "packages.request", &report);
    assert_eq!(report["in_use"], serde_json::Value::Null);
    assert_eq!(report["warnings"][0]["field"], "in_use");
}

fn listing() -> crate::packages::Collected {
    crate::packages::Collected::Dpkg(crate::packages::Listing {
        packages: vec![crate::packages::Package {
            name: "openssh-server".into(),
            version: "1:10.0p1-7".into(),
            architecture: "amd64".into(),
            source: Some("openssh".into()),
        }],
        ..Default::default()
    })
}

fn report_with(found: &Collected) -> serde_json::Value {
    decode(&crate::report::packages::encode_with(
        "00000000-0000-4000-8000-000000000001",
        "2026-01-01T12:00:00Z",
        &listing(),
        Some(found),
    ))
}

fn decode(encoded: &crate::report::packages::Encoded) -> serde_json::Value {
    use std::io::Read;
    let mut json = String::new();
    flate2::read::GzDecoder::new(&encoded.body[..])
        .read_to_string(&mut json)
        .unwrap();
    serde_json::from_str(&json).unwrap()
}

#[test]
fn only_fixed_commands_run_and_unit_names_follow_a_double_dash() {
    let host = debian_host();
    collect(&host, &Scan::Off, &mut scan::Memo::default(), None);
    let runs: Vec<String> = host
        .log()
        .into_iter()
        .filter(|l| l.starts_with("run "))
        .collect();
    assert_eq!(runs.len(), 3, "{runs:?}");
    assert!(
        runs[0]
            == "run /usr/bin/systemctl list-sockets --all --show-types --full --no-legend --no-pager",
        "{runs:?}"
    );
    assert!(
        runs[1].starts_with("run /usr/bin/systemctl list-units --type=service --state=running"),
        "{runs:?}"
    );
    assert!(
        runs[2].starts_with("run /usr/bin/systemctl show --no-pager --property=Id,ExecStart -- cron.service cups.service"),
        "{runs:?}"
    );
    // Nothing outside the sources is read.
    for line in host.log().iter().filter(|l| l.starts_with("read ")) {
        assert!(
            line.starts_with("read /proc/net/") || line.starts_with("read /var/lib/dpkg/info/"),
            "{line}"
        );
    }
    assert!(!host.log().iter().any(|l| l.contains("md5sums")));
}

#[test]
fn what_cannot_be_read_whole_is_null_with_a_warning() {
    type Break = Box<dyn Fn(&mut TestHost)>;
    let cases: Vec<(&str, Break)> = vec![
        ("sock_diag", Box::new(|h: &mut TestHost| h.sockets = None)),
        (
            "/sys/fs/cgroup",
            Box::new(|h: &mut TestHost| h.cgroups = None),
        ),
        (
            "/proc/net/tcp",
            Box::new(|h: &mut TestHost| {
                h.files.remove("/proc/net/tcp");
            }),
        ),
        (
            "/proc/net/udp",
            Box::new(|h: &mut TestHost| {
                h.files.insert(
                    "/proc/net/udp".into(),
                    format!("{TCP_HEADER}garbage\n").into_bytes(),
                );
            }),
        ),
        (
            "systemctl list-units",
            Box::new(|h: &mut TestHost| {
                h.commands.remove("list-units");
            }),
        ),
        (
            "systemctl show",
            Box::new(|h: &mut TestHost| {
                h.commands
                    .insert("show".into(), Ok(b"Id=cron.service\n".to_vec()));
            }),
        ),
        (
            "/var/lib/dpkg/info",
            Box::new(|h: &mut TestHost| {
                h.dirs.remove("/var/lib/dpkg/info");
            }),
        ),
        (
            "samba.list",
            Box::new(|h: &mut TestHost| {
                h.files.remove("/var/lib/dpkg/info/samba.list");
            }),
        ),
    ];
    for (what, breaks) in cases {
        let mut host = debian_host();
        breaks(&mut host);
        let found = collect(&host, &Scan::Off, &mut scan::Memo::default(), None);
        assert_eq!(found.in_use, None, "{what}");
        assert_eq!(found.warnings.len(), 1, "{what}: {:?}", found.warnings);
        assert!(
            found.warnings[0].contains(what),
            "{what}: {:?}",
            found.warnings
        );
    }
}

#[test]
fn ipv6_turned_off_is_not_an_error() {
    let mut host = debian_host();
    host.files.remove("/proc/net/tcp6");
    host.files.remove("/proc/net/udp6");
    let found = collect(&host, &Scan::Off, &mut scan::Memo::default(), None);
    assert!(found.warnings.is_empty(), "{:?}", found.warnings);
    assert!(found.in_use.is_some());
}

#[test]
fn without_systemds_socket_list_in_use_is_null() {
    // All or nothing (review of #268, S2): socket-activated services would otherwise drop out.
    let mut host = debian_host();
    host.commands.remove("list-sockets");
    let found = collect(&host, &Scan::Off, &mut scan::Memo::default(), None);
    assert_eq!(found.in_use, None);
    assert_eq!(found.warnings.len(), 1);
    assert!(
        found.warnings[0].contains("socket activation"),
        "{:?}",
        found.warnings
    );
}

#[test]
fn the_cgroup_walk_stays_inside_system_slice_and_init_scope() {
    let host = debian_host();
    collect(&host, &Scan::Off, &mut scan::Memo::default(), None);
    let walks: Vec<String> = host
        .log()
        .into_iter()
        .filter(|l| l.starts_with("walk "))
        .collect();
    assert_eq!(
        walks,
        [
            "walk /sys/fs/cgroup/system.slice",
            "walk /sys/fs/cgroup/init.scope"
        ]
    );
}

#[test]
fn a_host_with_nothing_listening_needs_no_cgroup_walk() {
    let mut host = debian_host();
    host.files
        .insert("/proc/net/tcp".into(), TCP_HEADER.as_bytes().to_vec());
    host.files
        .insert("/proc/net/tcp6".into(), TCP_HEADER.as_bytes().to_vec());
    host.files
        .insert("/proc/net/udp".into(), TCP_HEADER.as_bytes().to_vec());
    host.cgroups = None;
    let in_use = collect(&host, &Scan::Off, &mut scan::Memo::default(), None)
        .in_use
        .expect("in use");
    assert!(in_use.listening.is_empty());
    assert_eq!(in_use.unnamed_listeners, Unnamed::default());
    assert_eq!(in_use.services.len(), 5);
}

#[test]
fn too_many_units_is_null() {
    let mut host = debian_host();
    let many: String = (0..1001)
        .map(|i| format!("svc{i}.service loaded active running X\n"))
        .collect();
    host.commands
        .insert("list-units".into(), Ok(many.into_bytes()));
    let found = collect(&host, &Scan::Off, &mut scan::Memo::default(), None);
    assert_eq!(found.in_use, None);
    assert!(found.warnings[0].contains("1000"), "{:?}", found.warnings);
}

// --- /proc/net -------------------------------------------------------------------------------------

#[test]
fn proc_net_lines_are_read_and_classified() {
    let sockets = sockets::parse(tcp().as_bytes(), false).unwrap();
    assert_eq!(
        sockets.len(),
        6,
        "the established connection is not listening"
    );
    assert_eq!(sockets[0].address.to_string(), "0.0.0.0");
    assert_eq!(sockets[0].port, 22);
    assert!(!sockets[0].loopback());
    assert_eq!(sockets[1].address.to_string(), "192.0.2.10");
    assert_eq!(sockets[1].port, 445);
    assert!(sockets[2].loopback());
    let v6 = sockets::parse(tcp6().as_bytes(), false).unwrap();
    assert_eq!(v6[0].address.to_string(), "::");
    assert!(!v6[0].loopback());
    let loopback6 = format!(
        "{TCP_HEADER}   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 4001\n\
   1: 0000000000000000FFFF00000100007F:0016 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 4002\n"
    );
    let v6 = sockets::parse(loopback6.as_bytes(), false).unwrap();
    assert_eq!(v6[0].address.to_string(), "::1");
    assert!(v6[0].loopback());
    assert!(v6[1].loopback(), "{}", v6[1].address);
    let bound = sockets::parse(udp().as_bytes(), true).unwrap();
    assert_eq!(
        bound.len(),
        1,
        "the connected UDP socket is not bound for listening"
    );
    assert_eq!(bound[0].address.to_string(), "127.0.0.53");
    // UDP state 07 is the only bound state; TCP state 07 is a closed socket.
    assert!(sockets::parse(udp().as_bytes(), false).unwrap().is_empty());
}

#[test]
fn a_proc_net_line_that_cannot_be_read_is_an_error() {
    for bad in [
        "   0: 00000000:0016\n",
        "   0: 0000:0016 00000000:0000 0A 0:0 0:0 0 0 0 1\n",
        "   0: 00000000:zzzz 00000000:0000 0A 0:0 0:0 0 0 0 1\n",
        "   0: 00000000:0016 00000000:0000 0A 0:0 0:0 0 0 0 x\n",
        "   0: 00000000:0016 00000000:0000 GG 0:0 0:0 0 0 0 1\n",
    ] {
        assert!(
            sockets::parse(format!("{TCP_HEADER}{bad}").as_bytes(), false).is_err(),
            "{bad}"
        );
    }
    assert!(sockets::parse(b"\xff\n", false).is_err());
    assert!(
        sockets::parse(format!("{TCP_HEADER}\n").as_bytes(), false)
            .unwrap()
            .is_empty()
    );
}

// --- sock_diag ---------------------------------------------------------------------------------------

/// One reply message as the kernel builds it.
fn diag_message(sequence: u32, inode: u32, cgroup: Option<u64>) -> Vec<u8> {
    let mut body = vec![0u8; 72];
    body[0] = libc::AF_INET as u8;
    body[1] = 10;
    body[68..72].copy_from_slice(&inode.to_ne_bytes());
    // An attribute before the cgroup id, as the kernel sends several.
    body.extend_from_slice(&5u16.to_ne_bytes());
    body.extend_from_slice(&8u16.to_ne_bytes()); // INET_DIAG_SHUTDOWN
    body.extend_from_slice(&[0, 0, 0, 0]);
    if let Some(cgroup) = cgroup {
        body.extend_from_slice(&12u16.to_ne_bytes());
        body.extend_from_slice(&21u16.to_ne_bytes());
        body.extend_from_slice(&cgroup.to_ne_bytes());
    }
    header(20, sequence, &body)
}

fn header(kind: u16, sequence: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&2u16.to_ne_bytes());
    out.extend_from_slice(&sequence.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(body);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

#[test]
fn a_sock_diag_request_is_a_dump_of_one_family_and_protocol() {
    let request = netlink::request(libc::AF_INET6 as u8, libc::IPPROTO_UDP as u8, 1 << 7, 3);
    assert_eq!(request.len(), 72);
    assert_eq!(u32::from_ne_bytes(request[0..4].try_into().unwrap()), 72);
    assert_eq!(u16::from_ne_bytes(request[4..6].try_into().unwrap()), 20);
    assert_eq!(u16::from_ne_bytes(request[6..8].try_into().unwrap()), 0x301);
    assert_eq!(u32::from_ne_bytes(request[8..12].try_into().unwrap()), 3);
    assert_eq!(request[16], libc::AF_INET6 as u8);
    assert_eq!(request[17], libc::IPPROTO_UDP as u8);
    assert_eq!(
        u32::from_ne_bytes(request[20..24].try_into().unwrap()),
        1 << 7
    );
    assert!(request[24..].iter().all(|b| *b == 0));
}

#[test]
fn sock_diag_replies_give_each_socket_its_cgroup() {
    let mut bytes = diag_message(1, 1001, Some(11));
    bytes.extend(diag_message(9, 5555, Some(99))); // another request's: skipped
    bytes.extend(diag_message(1, 1002, Some(12)));
    let mut found = Vec::new();
    assert_eq!(netlink::parse(&bytes, 1, &mut found), Ok(false));
    assert_eq!(
        found,
        [
            SocketCgroup {
                inode: 1001,
                cgroup: 11
            },
            SocketCgroup {
                inode: 1002,
                cgroup: 12
            }
        ]
    );
    assert_eq!(
        netlink::parse(&header(3, 1, &[0; 4]), 1, &mut found),
        Ok(true)
    );
    assert_eq!(netlink::parse(&[], 1, &mut found), Ok(false));
}

#[test]
fn sock_diag_errors_and_short_replies_are_errors() {
    let mut found = Vec::new();
    let refused = header(2, 1, &(-libc::EPERM).to_ne_bytes());
    let message = netlink::parse(&refused, 1, &mut found).unwrap_err();
    assert!(message.contains("refused"), "{message}");
    let no_cgroup = diag_message(1, 1001, None);
    let message = netlink::parse(&no_cgroup, 1, &mut found).unwrap_err();
    assert!(message.contains("5.7"), "{message}");
    assert!(netlink::parse(&header(20, 1, &[0; 10]), 1, &mut found).is_err());
    let mut lying = diag_message(1, 1, Some(1));
    lying[0..4].copy_from_slice(&4096u32.to_ne_bytes());
    assert!(netlink::parse(&lying, 1, &mut found).is_err());
}

#[test]
fn the_real_sock_diag_answers_without_privilege() {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    // This test runs as an ordinary user in CI: the dump needs no capability. A listener of our own
    // must be in it, with the cgroup this process is in.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let inode = std::fs::metadata(format!("/proc/self/fd/{}", listener.as_raw_fd()))
        .unwrap()
        .ino();
    match netlink::dump(super::MAX_SOCKETS) {
        Ok(sockets) => {
            let ours = sockets
                .iter()
                .find(|s| s.inode == inode)
                .expect("our listener is in the dump");
            // cgroup v2: the id is the inode of our cgroup's directory.
            if let Ok(text) = std::fs::read_to_string("/proc/self/cgroup")
                && let Some(path) = text.lines().find_map(|l| l.strip_prefix("0::"))
                && let Ok(meta) = std::fs::metadata(format!("/sys/fs/cgroup{path}"))
            {
                assert_eq!(ours.cgroup, meta.ino());
            }
            let proc_net = std::fs::read("/proc/net/tcp").unwrap();
            assert!(
                sockets::parse(&proc_net, false)
                    .unwrap()
                    .iter()
                    .any(|s| s.inode == inode)
            );
        }
        // A sandbox without netlink (some containers): nothing to check here.
        Err(e) => eprintln!("sock_diag is not available here: {e}"),
    }
}

// --- units -------------------------------------------------------------------------------------------

#[test]
fn a_cgroup_names_a_service_only_inside_system_slice() {
    use units::Owner::*;
    assert_eq!(
        units::unit_of("system.slice/ssh.service"),
        Service("ssh.service".into())
    );
    assert_eq!(
        units::unit_of("system.slice/system-getty.slice/getty@tty1.service"),
        Service("getty@tty1.service".into())
    );
    assert_eq!(
        units::unit_of("system.slice/docker.service/sub/x.service"),
        Service("docker.service".into())
    );
    assert_eq!(units::unit_of("init.scope"), Systemd);
    for other in [
        "",
        "system.slice",
        "system.slice/docker-01.scope",
        "user.slice/user-1000.slice/user@1000.service",
        "machine.slice/x.service",
        "system.slice/--help.service",
        "system.slice/a b.service",
    ] {
        assert_eq!(units::unit_of(other), Other, "{other}");
    }
}

#[test]
fn service_names_passed_to_systemctl_are_checked() {
    assert!(units::service_name("ssh.service"));
    assert!(units::service_name(
        "systemd-fsck@dev-disk-by\\x2duuid-01.service"
    ));
    assert!(!units::service_name("ssh@.service"));
    assert!(!units::service_name("-x.service"));
    assert!(!units::service_name(".service"));
    assert!(!units::service_name("ssh.socket"));
    assert!(!units::service_name("a;b.service"));
    assert!(!units::service_name(&format!(
        "{}.service",
        "a".repeat(260)
    )));
}

#[test]
fn systemctl_show_gives_each_unit_its_executables_and_nothing_else() {
    let output = "Id=a.service\nExecStart={ path=/usr/bin/a ; argv[]=/usr/bin/a -x ; ignore_errors=no } ; { path=/usr/bin/b ; argv[]=b }\n\nId=none.service\n\nExecStart={ path=relative ; argv[]=x }\nId=c.service\n";
    let units = units::parse_show(output.as_bytes(), 3).unwrap();
    assert_eq!(units["a.service"], ["/usr/bin/a", "/usr/bin/b"]);
    assert!(units["none.service"].is_empty());
    assert!(units["c.service"].is_empty());
    assert!(units::parse_show(output.as_bytes(), 2).is_err());
    assert!(units::parse_show(b"ExecStart=\n", 1).is_err());
    assert!(units::parse_show(b"\xff", 1).is_err());
}

#[test]
fn list_sockets_gives_ip_listeners_and_their_services() {
    let output = "\
[::]:22          Stream    ssh.socket     ssh.service
0.0.0.0:80       Stream    web.socket     web-a.service, web-b.service
127.0.0.1:631    Datagram  cups.socket    cups.service
*:9              Stream    tpl.socket     tpl@.service
/run/x.sock      Stream    x.socket       x.service
vsock:2:1        Stream    v.socket       v.service
[fe80::1%eth0]:5 Stream    odd.socket     odd.service
";
    let found = units::parse_list_sockets(output.as_bytes()).unwrap();
    assert_eq!(found.len(), 4, "{found:?}");
    assert_eq!(found[0].address, None);
    assert_eq!(found[0].port, 22);
    assert_eq!(found[0].services, ["ssh.service"]);
    assert_eq!(found[1].services, ["web-a.service", "web-b.service"]);
    assert_eq!(found[2].address.unwrap().to_string(), "127.0.0.1");
    assert!(found[2].udp && !found[0].udp);
    assert!(found[3].services.is_empty(), "a template is not named");
    assert!(units::parse_list_sockets(b"\xff").is_err());
}

#[test]
fn a_socket_systemd_holds_is_matched_by_protocol_port_and_address() {
    let socket = |address: &str, port, udp| Socket {
        inode: 1,
        address: address.parse().unwrap(),
        port,
        udp,
    };
    let activated = units::parse_list_sockets(
        b"0.0.0.0:22 Stream ssh.socket ssh.service\n\
          127.0.0.1:631 Stream cups.socket cups.service\n\
          [::]:631 Stream all.socket cups-all.service\n\
          0.0.0.0:631 Datagram browsed.socket cups-browsed.service\n\
          0.0.0.0:80 Stream w.socket a.service, b.service\n",
    )
    .unwrap();
    let service = |s: &Socket| match match_activated(s, &activated) {
        Owner::Service(name) => Some(name),
        _ => None,
    };
    assert_eq!(
        service(&socket("0.0.0.0", 22, false)).as_deref(),
        Some("ssh.service")
    );
    assert_eq!(
        service(&socket("::", 22, false)).as_deref(),
        Some("ssh.service")
    );
    // The entry on the socket's own address wins over the wildcard one, whichever comes first.
    assert_eq!(
        service(&socket("127.0.0.1", 631, false)).as_deref(),
        Some("cups.service")
    );
    // Another address on the same port: the wildcard entry.
    assert_eq!(
        service(&socket("192.0.2.1", 631, false)).as_deref(),
        Some("cups-all.service")
    );
    // The protocol must match (review of #268, S2).
    assert_eq!(
        service(&socket("192.0.2.1", 631, true)).as_deref(),
        Some("cups-browsed.service")
    );
    assert_eq!(service(&socket("0.0.0.0", 22, true)), None);
    assert_eq!(
        service(&socket("0.0.0.0", 80, false)),
        None,
        "two services: not named"
    );
    assert_eq!(service(&socket("0.0.0.0", 23, false)), None);
    let specific_only =
        units::parse_list_sockets(b"127.0.0.1:9 Stream x.socket x.service\n").unwrap();
    assert_eq!(
        match_activated(&socket("0.0.0.0", 9, false), &specific_only),
        Owner::Other
    );
}

/// `systemctl list-sockets --all --show-types --full --no-legend --no-pager` on Debian 13 (systemd 257),
/// with a socket-activated SSH on every address and a CUPS one on loopback, as systemd prints it.
const REAL_LIST_SOCKETS: &str = "\
/dev/log                        Datagram         systemd-journald-dev-log.socket systemd-journald.service
/run/dbus/system_bus_socket     Stream           dbus.socket                     dbus.service
/run/initctl                    FIFO             systemd-initctl.socket          systemd-initctl.service
/run/systemd/journal/socket     Datagram         systemd-journald.socket         systemd-journald.service
/run/systemd/journal/stdout     Stream           systemd-journald.socket         systemd-journald.service
/run/udev/control               SequentialPacket systemd-udevd-control.socket    systemd-udevd.service
127.0.0.1:631                   Stream           cups.socket                     cups.service
[::]:22                         Stream           ssh.socket                      ssh.service
audit 1                         Netlink          systemd-journald-audit.socket   systemd-journald.service
kobject-uevent 1                Netlink          systemd-udevd-kernel.socket     systemd-udevd.service
";

#[test]
fn real_list_sockets_output_names_socket_activated_services() {
    // Review of #268, S1: the TYPE column is there only with --show-types.
    let found = units::parse_list_sockets(REAL_LIST_SOCKETS.as_bytes()).unwrap();
    assert_eq!(found.len(), 2, "{found:?}");
    let ssh = Socket {
        inode: 1,
        address: "::".parse().unwrap(),
        port: 22,
        udp: false,
    };
    let cups = Socket {
        inode: 2,
        address: "127.0.0.1".parse().unwrap(),
        port: 631,
        udp: false,
    };
    assert_eq!(
        match_activated(&ssh, &found),
        Owner::Service("ssh.service".into())
    );
    assert_eq!(
        match_activated(&cups, &found),
        Owner::Service("cups.service".into())
    );
    // The same lines without --show-types name nothing: the agent must ask for the column.
    let without: String = REAL_LIST_SOCKETS
        .lines()
        .map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            format!("{} {}\n", f[0], f[f.len() - 2..].join(" "))
        })
        .collect();
    assert!(
        units::parse_list_sockets(without.as_bytes())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn list_sockets_lines_without_a_known_type_are_skipped() {
    let found = units::parse_list_sockets(
        b"0.0.0.0:22 ssh.socket ssh.service\n/run/x FIFO x.socket x.service\n0.0.0.0:7 SequentialPacket s.socket s.service\n",
    )
    .unwrap();
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_cut_short_sock_diag_dump_is_an_error() {
    let mut found = Vec::new();
    let message =
        netlink::parse(&header(3, 1, &(-libc::EINTR).to_ne_bytes()), 1, &mut found).unwrap_err();
    assert!(message.contains("ended early"), "{message}");
}

#[test]
fn a_multibyte_character_across_a_word_boundary_is_an_error_not_a_panic() {
    // Review of #268, N2: 32 bytes, with the 8th and 9th in one character, so slicing would panic.
    let address = format!("0000000\u{e9}{}", "0".repeat(23));
    assert_eq!(address.len(), 32);
    let line = format!(
        "{TCP_HEADER}   0: {address}:0016 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 1\n"
    );
    assert!(sockets::parse(line.as_bytes(), false).is_err());
}

#[test]
fn a_non_ascii_address_is_an_error_not_a_panic() {
    let line = format!("{TCP_HEADER}   0: 0000\u{e9}0000:0016 00000000:0000 0A 0:0 0:0 0 0 0 1\n");
    assert!(sockets::parse(line.as_bytes(), false).is_err());
}

#[test]
fn an_argument_that_looks_like_a_path_is_not_an_executable() {
    let output = "Id=a.service\nExecStart={ path=/usr/bin/a ; argv[]=/usr/bin/a --socket-path=/usr/lib/x ; ignore_errors=no }\n";
    let units = units::parse_show(output.as_bytes(), 1).unwrap();
    assert_eq!(units["a.service"], ["/usr/bin/a"]);
}

#[test]
fn a_report_too_large_with_in_use_keeps_the_listing_and_drops_in_use() {
    // Review of #268, N4: the listing must not become `unreadable` because of in_use.
    let packages: Vec<crate::packages::Package> = (0..20_000)
        .map(|i| crate::packages::Package {
            name: format!("{:a<120}{i:05}", "p"),
            version: "1.0".into(),
            architecture: "amd64".into(),
            source: None,
        })
        .collect();
    let listing = crate::packages::Collected::Dpkg(crate::packages::Listing {
        packages,
        ..Default::default()
    });
    let libraries: Vec<Library> = (0..20_000)
        .map(|i| Library {
            package: format!("lib{i:05}-with-a-long-name"),
            stale: false,
        })
        .collect();
    let found = Collected {
        in_use: Some(InUse {
            listening: vec![],
            services: vec![],
            unnamed_listeners: Unnamed::default(),
            library_scan: "ran",
            libraries: Some(libraries),
            native: Some(vec![]),
            scanned_at: Some("2026-11-20T12:00:00Z".into()),
            complete: true,
        }),
        warnings: vec![],
    };
    let encoded = crate::report::packages::encode_with(
        "00000000-0000-4000-8000-000000000001",
        "2026-11-20T12:00:00Z",
        &listing,
        Some(&found),
    );
    assert_eq!(encoded.refused, None);
    let report = decode(&encoded);
    assert_eq!(report["manager"], "dpkg");
    assert_eq!(report["packages"].as_array().unwrap().len(), 20_000);
    assert_eq!(report["in_use"], serde_json::Value::Null);
    assert!(
        report["warnings"][0]["message"]
            .as_str()
            .unwrap()
            .contains("left out")
    );
}

// --- dpkg file lists ---------------------------------------------------------------------------------

#[test]
fn paths_are_looked_up_on_both_sides_of_the_usr_merge() {
    assert_eq!(
        owners::aliases("/usr/sbin/sshd"),
        ["/usr/sbin/sshd", "/sbin/sshd"]
    );
    assert_eq!(
        owners::aliases("/lib/x86_64-linux-gnu/libc.so.6"),
        [
            "/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libc.so.6"
        ]
    );
    assert_eq!(owners::aliases("/opt/tool"), ["/opt/tool"]);
    assert_eq!(owners::aliases("/usr/share/x"), ["/usr/share/x"]);
}

#[test]
fn nothing_wanted_reads_no_list() {
    let host = TestHost::default();
    let ctx = Ctx::new(&host, BUDGET);
    assert!(owners::owners(&ctx, &HashSet::new()).unwrap().is_empty());
    assert!(host.log().is_empty());
}

// --- the library scan --------------------------------------------------------------------------------

const MAPS: &str = "\
55d0c0a00000-55d0c0a28000 r--p 00000000 fe:01 1311  /usr/sbin/sshd
7f1a2b000000-7f1a2b028000 r--p 00000000 fe:01 2222  /usr/lib/x86_64-linux-gnu/libc.so.6
7f1a2c000000-7f1a2c100000 r-xp 00000000 fe:01 3333  /usr/lib/x86_64-linux-gnu/libssl.so.3 (deleted)
7f1a2d000000-7f1a2d001000 rw-p 00000000 00:00 0
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0  [stack]
7f1a2e000000-7f1a2e001000 r--p 00000000 fe:01 4444  /srv/data/a file with spaces
";

#[test]
fn maps_lines_give_files_and_deleted_ones() {
    let files = scan::parse_maps(MAPS.as_bytes());
    assert_eq!(
        files,
        [
            ("/usr/sbin/sshd".to_owned(), false),
            ("/usr/lib/x86_64-linux-gnu/libc.so.6".to_owned(), false),
            ("/usr/lib/x86_64-linux-gnu/libssl.so.3".to_owned(), true),
            ("/srv/data/a file with spaces".to_owned(), false),
        ]
    );
}

fn scan_host() -> TestHost {
    let mut host = TestHost::default()
        .file("/proc/1/maps", "")
        .file("/proc/812/maps", MAPS)
        .file(
            "/proc/900/maps",
            "7f00-7f01 r--p 0 fe:01 2222 /usr/lib/x86_64-linux-gnu/libc.so.6\n",
        )
        .file("/var/lib/dpkg/info/openssh-server.list", "/usr/sbin/sshd\n")
        .file(
            "/var/lib/dpkg/info/libc6:amd64.list",
            "/lib/x86_64-linux-gnu/libc.so.6\n",
        )
        .file(
            "/var/lib/dpkg/info/libssl3t64:amd64.list",
            "/usr/lib/x86_64-linux-gnu/libssl.so.3\n",
        )
        .file("/var/lib/dpkg/info/libidle.list", "/usr/lib/libidle.so.1\n")
        .file("/usr/sbin/sshd", "\x7fELF....")
        .file("/lib/x86_64-linux-gnu/libc.so.6", "\x7fELF....")
        .file("/usr/lib/libidle.so.1", "\x7fELF....");
    host.dirs.insert(
        "/proc".into(),
        ["1", "812", "900", "933", "self", "net", "sys"]
            .map(String::from)
            .to_vec(),
    );
    host.dirs.insert(
        "/var/lib/dpkg/info".into(),
        [
            "libc6:amd64.list",
            "libidle.list",
            "libssl3t64:amd64.list",
            "openssh-server.list",
        ]
        .map(String::from)
        .to_vec(),
    );
    host
}

#[test]
fn the_scan_names_packages_in_use_and_stale_ones() {
    // Process 933 ended between the listing and its read: skipped.
    let host = scan_host();
    let output = scan::scan(&host).unwrap();
    let libraries = output.libraries;
    assert_eq!(
        libraries,
        [
            Library {
                package: "libc6".into(),
                stale: false
            },
            Library {
                package: "libssl3t64".into(),
                stale: true
            },
            Library {
                package: "openssh-server".into(),
                stale: false
            },
        ]
    );
    // A library only a stopped service would use is not in the list, and it is native: idle.
    assert!(!libraries.iter().any(|l| l.package == "libidle"));
    assert_eq!(output.native, ["libc6", "libidle", "openssh-server"]);
}

#[test]
fn only_native_code_packages_can_be_judged() {
    // Owner decision 2026-11-20 (review of #268, B2): interpreted code is read, not mapped.
    let mut host = scan_host()
        .file(
            "/var/lib/dpkg/info/python3-urllib3.list",
            "/usr/lib/python3/dist-packages/urllib3/__init__.py\n",
        )
        .file(
            "/var/lib/dpkg/info/mixed.list",
            "/usr/lib/mixed/libm.so.1\n/usr/share/mixed/tool.pl\n",
        )
        .file(
            "/var/lib/dpkg/info/scripted.list",
            "/usr/bin/scripted\n/usr/lib/libscripted.so.1\n",
        )
        .file(
            "/var/lib/dpkg/info/docs-only.list",
            "/usr/share/doc/docs-only/example.py\n/usr/lib/libdocs.so.1\n",
        )
        .file(
            "/var/lib/dpkg/info/data-only.list",
            "/usr/share/data-only/table.bin\n",
        )
        .file(
            "/var/lib/dpkg/info/secret.list",
            "/usr/lib/libsecret-ok.so.0\n/usr/lib/libsecret.so.0\n",
        )
        .file("/usr/lib/libsecret-ok.so.0", "\x7fELF....")
        .file("/usr/lib/mixed/libm.so.1", "\x7fELF....")
        .file("/usr/bin/scripted", "#!/bin/sh\nexit 0\n")
        .file("/usr/lib/libscripted.so.1", "\x7fELF....")
        .file("/usr/lib/libdocs.so.1", "\x7fELF....");
    host.denied.insert("/usr/lib/libsecret.so.0".into());
    let names = host.dirs.get_mut("/var/lib/dpkg/info").unwrap();
    names.extend(
        [
            "data-only.list",
            "docs-only.list",
            "mixed.list",
            "python3-urllib3.list",
            "scripted.list",
            "secret.list",
        ]
        .map(String::from),
    );
    names.sort();
    let native = scan::scan(&host).unwrap().native;
    assert_eq!(
        native,
        ["docs-only", "libc6", "libidle", "openssh-server"],
        "a package with interpreted code, a script, no ELF file, or an unreadable code file cannot be judged"
    );
}

#[test]
fn package_managed_files_and_other_files_have_limits_of_their_own() {
    let mut host = scan_host();
    let maps = |prefix: &str, n: usize| -> Vec<u8> {
        (0..n)
            .map(|i| format!("7f00-7f01 r--p 0 fe:01 1 {prefix}/{i}.so\n"))
            .collect::<String>()
            .into_bytes()
    };
    // As many other files as allowed do not push package-managed ones out, and the reverse.
    let mut both = maps("/home/user/data", scan::MAX_OTHER_PATHS);
    both.extend(maps("/usr/lib/x", scan::MAX_PATHS - 10));
    host.files.insert("/proc/812/maps".into(), both);
    assert!(scan::scan(&host).is_ok());
    host.files.insert(
        "/proc/812/maps".into(),
        maps("/home/user/data", scan::MAX_OTHER_PATHS + 1),
    );
    let message = scan::scan(&host).unwrap_err();
    assert!(message.contains("50000 files elsewhere"), "{message}");
    host.files.insert(
        "/proc/812/maps".into(),
        maps("/usr/lib/x", scan::MAX_PATHS + 1),
    );
    let message = scan::scan(&host).unwrap_err();
    assert!(message.contains("50000 files under /usr"), "{message}");
}

#[test]
fn a_package_with_code_under_opt_is_never_native_and_is_named_when_mapped() {
    // Review of #268, B1: a vendor agent under /opt ran while it looked idle.
    let mut host = scan_host()
        .file(
            "/var/lib/dpkg/info/vendor-agent.list",
            "/opt/vendor/bin/agentd\n/usr/lib/libvendor.so.1\n",
        )
        .file(
            "/var/lib/dpkg/info/vendor-idle.list",
            "/opt/idle/lib/libidle.so\n/usr/lib/libvidle.so.1\n",
        )
        .file("/opt/vendor/bin/agentd", "\x7fELF....")
        .file("/opt/idle/lib/libidle.so", "\x7fELF....")
        .file("/usr/lib/libvendor.so.1", "\x7fELF....")
        .file("/usr/lib/libvidle.so.1", "\x7fELF....")
        .file(
            "/proc/900/maps",
            "7f00-7f01 r-xp 0 fe:01 9 /opt/vendor/bin/agentd\n",
        );
    host.executables.insert("/opt/vendor/bin/agentd".into());
    add_lists(&mut host, &["vendor-agent.list", "vendor-idle.list"]);
    let output = scan::scan(&host).unwrap();
    assert!(
        output.libraries.iter().any(|l| l.package == "vendor-agent"),
        "{:?}",
        output.libraries
    );
    assert!(!output.native.contains(&"vendor-agent".to_owned()));
    assert!(
        !output.native.contains(&"vendor-idle".to_owned()),
        "ELF code outside the scanned prefixes"
    );
}

#[test]
fn a_scan_out_of_time_fails_rather_than_judge_on_part_of_a_package() {
    // Review of #268, B2: the script read after the deadline would have left aaa-tool native.
    struct Slow(TestHost);
    impl Host for Slow {
        fn stat(&self, p: &Path) -> io::Result<Stat> {
            self.0.stat(p)
        }
        fn read(&self, p: &Path, m: u64) -> io::Result<Vec<u8>> {
            self.0.read(p, m)
        }
        fn list(&self, d: &Path, m: usize) -> io::Result<Vec<String>> {
            self.0.list(d, m)
        }
        fn run(&self, c: &Command) -> Result<Vec<u8>, RunError> {
            self.0.run(c)
        }
        fn inspect(&self, p: &Path) -> io::Result<crate::facts::host::Inspect> {
            self.0.inspect(p)
        }
        fn head(&self, p: &Path, n: usize) -> io::Result<Vec<u8>> {
            if p == Path::new("/usr/bin/aaa-tool") {
                std::thread::sleep(std::time::Duration::from_millis(1200));
            }
            self.0.head(p, n)
        }
    }
    let mut host = scan_host()
        .file(
            "/var/lib/dpkg/info/aaa-tool.list",
            "/usr/bin/aaa-tool\n/usr/sbin/aaa-tool-wrapper\n",
        )
        .file("/usr/bin/aaa-tool", "\x7fELF....")
        .file("/usr/sbin/aaa-tool-wrapper", "#!/bin/sh\n");
    add_lists(&mut host, &["aaa-tool.list"]);
    let message = scan::scan_within(&Slow(host), std::time::Duration::from_secs(1)).unwrap_err();
    assert!(message.contains("budget"), "{message}");
}

#[test]
fn a_script_anywhere_in_a_package_makes_it_not_native() {
    // Review of #268, S2: executable files anywhere, symlinks followed, and .sh files.
    let mut host = scan_host();
    type Pairs<'a> = &'a [(&'a str, &'a str)];
    let cases: [(&str, &str, Pairs, &[&str], Pairs); 5] = [
        (
            "hook-pkg",
            "/usr/lib/hook-pkg/libh.so.1\n/usr/lib/hook-pkg/hook\n",
            &[("/usr/lib/hook-pkg/hook", "#!/bin/sh\n")],
            &["/usr/lib/hook-pkg/hook"],
            &[],
        ),
        (
            "cron-pkg",
            "/usr/lib/libcron-pkg.so.1\n/etc/cron.daily/cron-pkg\n",
            &[("/etc/cron.daily/cron-pkg", "#!/bin/sh\n")],
            &["/etc/cron.daily/cron-pkg"],
            &[],
        ),
        (
            "job-pkg",
            "/usr/lib/libjob.so.1\n/usr/share/job-pkg/job.sh\n",
            &[("/usr/share/job-pkg/job.sh", "echo\n")],
            &[],
            &[],
        ),
        (
            "link-pkg",
            "/usr/lib/liblink.so.1\n/usr/bin/link-tool\n/usr/share/link-pkg/tool\n",
            &[("/usr/share/link-pkg/tool", "#!/usr/bin/perl\n")],
            &[],
            &[("/usr/bin/link-tool", "/usr/share/link-pkg/tool")],
        ),
        (
            "elf-pkg",
            "/usr/lib/libelf-pkg.so.1\n/usr/bin/elf-tool\n/usr/lib/libelf-pkg.so\n/usr/share/elf-pkg/data\n",
            &[("/usr/bin/elf-tool", "\x7fELF....")],
            &["/usr/bin/elf-tool"],
            &[("/usr/lib/libelf-pkg.so", "/usr/lib/libelf-pkg.so.1")],
        ),
    ];
    let mut lists = Vec::new();
    for (package, list, files, executables, links) in cases {
        host.files.insert(
            format!("/var/lib/dpkg/info/{package}.list"),
            list.as_bytes().to_vec(),
        );
        lists.push(format!("{package}.list"));
        let first = list.lines().next().unwrap();
        host.files.insert(first.into(), b"\x7fELF....".to_vec());
        for (path, text) in files {
            host.files.insert((*path).into(), text.as_bytes().to_vec());
        }
        host.files
            .insert("/usr/share/elf-pkg/data".into(), b"plain data".to_vec());
        host.executables
            .extend(executables.iter().map(|e| (*e).to_owned()));
        host.symlinks.extend(
            links
                .iter()
                .map(|(a, b)| ((*a).to_owned(), (*b).to_owned())),
        );
    }
    let names: Vec<&str> = lists.iter().map(String::as_str).collect();
    add_lists(&mut host, &names);
    let native = scan::scan(&host).unwrap().native;
    for package in ["hook-pkg", "cron-pkg", "job-pkg", "link-pkg"] {
        assert!(
            !native.contains(&package.to_owned()),
            "{package} is native: {native:?}"
        );
    }
    assert!(
        native.contains(&"elf-pkg".to_owned()),
        "ELF only, a library symlink, and data: native"
    );
}

#[test]
fn a_diverted_or_shared_file_marks_every_package_that_lists_it() {
    // Review of #268, S7.
    let mut host = scan_host()
        .file(
            "/var/lib/dpkg/info/libgl1.list",
            "/usr/lib/x86_64-linux-gnu/libGL.so.1\n",
        )
        .file(
            "/var/lib/dpkg/info/nvidia-glx.list",
            "/usr/lib/x86_64-linux-gnu/libGL.so.1\n",
        )
        .file("/usr/lib/x86_64-linux-gnu/libGL.so.1", "\x7fELF....")
        .file(
            "/proc/900/maps",
            "7f00-7f01 r-xp 0 fe:01 9 /usr/lib/x86_64-linux-gnu/libGL.so.1\n",
        );
    add_lists(&mut host, &["libgl1.list", "nvidia-glx.list"]);
    let libraries = scan::scan(&host).unwrap().libraries;
    for package in ["libgl1", "nvidia-glx"] {
        assert!(
            libraries.iter().any(|l| l.package == package),
            "{package}: {libraries:?}"
        );
    }
}

fn add_lists(host: &mut TestHost, lists: &[&str]) {
    let names = host.dirs.get_mut("/var/lib/dpkg/info").unwrap();
    names.extend(lists.iter().map(|l| (*l).to_owned()));
    names.sort();
}

#[test]
fn the_scan_fails_rather_than_report_part_of_the_processes() {
    let mut host = scan_host();
    host.dirs.insert(
        "/proc".into(),
        (0..=scan::MAX_PROCESSES).map(|i| i.to_string()).collect(),
    );
    assert!(scan::scan(&host).unwrap_err().contains("processes"));
    let mut host = scan_host();
    host.files
        .insert("/proc/812/maps".into(), vec![b'x'; 9 * 1024 * 1024]);
    assert!(scan::scan(&host).unwrap_err().contains("/proc/812/maps"));
}

#[test]
fn the_scan_unit_alone_carries_the_capability_and_has_no_network() {
    let command = scan::command("/usr/lib/fleet-agent/versions/1.2.3/fleet-agent");
    assert_eq!(command.programs, ["/usr/bin/systemd-run"]);
    let args = &command.args;
    for wanted in [
        "--unit=fleet-agent-library-scan.service",
        "--wait",
        "--pipe",
        "--collect",
        "--property=CapabilityBoundingSet=CAP_SYS_PTRACE",
        "--property=ProtectHome=yes",
        "--property=ProcSubset=pid",
        "--property=PrivateNetwork=yes",
        "--property=IPAddressDeny=any",
        "--property=RuntimeMaxSec=30",
        "--property=ProtectSystem=strict",
        "--property=NoNewPrivileges=yes",
    ] {
        assert!(args.iter().any(|a| a == wanted), "{wanted}: {args:?}");
    }
    let dash = args.iter().position(|a| a == "--").unwrap();
    assert_eq!(
        &args[dash + 1..],
        [
            "/usr/lib/fleet-agent/versions/1.2.3/fleet-agent",
            "library-scan"
        ]
    );
    // CAP_SYS_PTRACE alone (review of #268, S4): nothing reads other users' files.
    assert!(!args.iter().any(|a| a.contains("CAP_DAC")));
    // Nothing writable: no ReadWritePaths=, no StateDirectory=.
    assert!(
        !args
            .iter()
            .any(|a| a.contains("ReadWrite") || a.contains("StateDirectory"))
    );
    // The agent's own unit never carries it.
    let unit = include_str!("../install/fleet-agent.service");
    assert!(!unit.contains("CAP_SYS_PTRACE"));
    assert!(unit.contains("CapabilityBoundingSet=CAP_DAC_READ_SEARCH\n"));
}

#[test]
fn the_scan_result_is_checked_against_the_contract() {
    let ok = scan::parse_output(
        br#"{"libraries":[{"package":"openssl","stale":false},{"package":"libc6","stale":true}],"native":["openssl","libc6"]}"#,
    )
    .unwrap();
    assert_eq!(ok.libraries[0].package, "libc6");
    assert_eq!(ok.native, ["libc6", "openssl"]);
    for bad in [
        &br#"not json"#[..],
        br#"{"libraries":[]}"#,
        br#"{"libraries":[{"package":"Bad","stale":false}],"native":[]}"#,
        br#"{"libraries":[{"package":"a","stale":false},{"package":"a","stale":true}],"native":[]}"#,
        br#"{"libraries":[{"package":"a"}],"native":[]}"#,
        br#"{"libraries":[],"native":["a","a"]}"#,
        br#"{"libraries":[],"native":["Bad"]}"#,
    ] {
        assert!(scan::parse_output(bad).is_err());
    }
}

#[test]
fn with_the_scan_on_the_report_is_complete() {
    let host = debian_host().command(
        "--unit=fleet-agent-library-scan.service",
        Ok(r#"{"libraries":[{"package":"libc6","stale":false},{"package":"libssl3t64","stale":true}],"native":["libc6","libssl3t64","zlib1g"]}"#),
    );
    let found = collect(
        &host,
        &Scan::On(Ok("/usr/lib/fleet-agent/current/fleet-agent".into())),
        &mut scan::Memo::default(),
        None,
    );
    assert!(found.warnings.is_empty(), "{:?}", found.warnings);
    let in_use = found.in_use.as_ref().expect("in use");
    assert_eq!(in_use.library_scan, "ran");
    assert!(in_use.complete);
    assert_eq!(in_use.libraries.as_ref().unwrap().len(), 2);
    assert_eq!(in_use.native.as_ref().unwrap().len(), 3);
    assert!(in_use.scanned_at.is_some());
    contract::assert_conforms("v1", "packages.request", &report_with(&found));
}

#[test]
fn the_scan_runs_at_most_once_an_hour_however_often_reports_are_asked_for() {
    // Owner decision 2026-11-20 (review of #268, S3).
    let host = debian_host().command(
        "--unit=fleet-agent-library-scan.service",
        Ok(r#"{"libraries":[],"native":[]}"#),
    );
    let scan = Scan::On(Ok("/usr/lib/fleet-agent/current/fleet-agent".into()));
    let mut memo = scan::Memo::default();
    let first = collect(&host, &scan, &mut memo, None).in_use.unwrap();
    let again = collect(&host, &scan, &mut memo, None).in_use.unwrap();
    assert_eq!(first.scanned_at, again.scanned_at);
    let runs = |host: &TestHost| {
        host.log()
            .iter()
            .filter(|l| l.contains("systemd-run"))
            .count()
    };
    assert_eq!(runs(&host), 1);

    let mut memo = scan::Memo::default();
    let start = std::time::Instant::now();
    let mut count = 0;
    let scanned = |n| scan::Scanned {
        result: Ok(scan::Output {
            libraries: vec![],
            native: vec![],
        }),
        at: format!("{n}"),
    };
    let a = memo.get(start, || {
        count += 1;
        scanned(1)
    });
    let b = memo.get(
        start + scan::EVERY - std::time::Duration::from_secs(1),
        || {
            count += 1;
            scanned(2)
        },
    );
    let c = memo.get(start + scan::EVERY, || {
        count += 1;
        scanned(3)
    });
    assert_eq!(
        (a.at.as_str(), b.at.as_str(), c.at.as_str(), count),
        ("1", "1", "3", 2)
    );
}

#[test]
fn a_failed_scan_is_not_retried_within_the_hour() {
    let host = debian_host();
    let scan = Scan::On(Ok("/usr/lib/fleet-agent/current/fleet-agent".into()));
    let mut memo = scan::Memo::default();
    for _ in 0..3 {
        let found = collect(&host, &scan, &mut memo, None);
        assert_eq!(found.in_use.unwrap().library_scan, "failed");
    }
    assert_eq!(
        host.log()
            .iter()
            .filter(|l| l.contains("systemd-run"))
            .count(),
        1
    );
}

#[test]
fn a_failed_scan_says_so_and_keeps_the_services() {
    for (scan, why) in [
        (
            Scan::On(Err("the agent's own path cannot be read".into())),
            "own path",
        ),
        (Scan::On(Ok("relative/fleet-agent".into())), "absolute"),
        (
            Scan::On(Ok("/usr/lib/fleet-agent/current/fleet-agent".into())),
            "library scan unit",
        ),
    ] {
        let host = debian_host();
        let found = collect(&host, &scan, &mut scan::Memo::default(), None);
        let in_use = found.in_use.as_ref().expect("in use");
        assert_eq!(in_use.library_scan, "failed");
        assert!(!in_use.complete);
        assert_eq!(in_use.libraries, None);
        assert!(!in_use.listening.is_empty());
        assert_eq!(found.warnings.len(), 1);
        assert!(
            found.warnings[0].contains(why),
            "{why}: {:?}",
            found.warnings
        );
        contract::assert_conforms("v1", "packages.request", &report_with(&found));
    }
    // With the scan off, systemd-run is never run.
    let host = debian_host();
    collect(&host, &Scan::Off, &mut scan::Memo::default(), None);
    assert!(!host.log().iter().any(|l| l.contains("systemd-run")));
}

#[test]
fn the_real_directory_walk_gives_inodes_breadth_first() {
    use std::os::unix::fs::MetadataExt;
    let dir = crate::test_support::TempDir::new();
    std::fs::create_dir_all(dir.path("a/b")).unwrap();
    std::fs::create_dir_all(dir.path("c")).unwrap();
    std::fs::write(dir.path("a/file"), b"").unwrap();
    let host = crate::facts::host::RealHost::new();
    let found = host.directories(&dir.path(""), 10).unwrap();
    let paths: Vec<&str> = found.iter().map(|(_, p)| p.as_str()).collect();
    assert_eq!(paths, ["", "a", "c", "a/b"]);
    assert_eq!(
        found[3].0,
        std::fs::metadata(dir.path("a/b")).unwrap().ino()
    );
    assert!(host.directories(&dir.path(""), 3).is_err());
}

/// `cargo test in_use_on_this_host -- --ignored --nocapture`; prints the time it took too.
#[test]
#[ignore = "reads the real host; run by hand"]
fn in_use_on_this_host() {
    let host = crate::facts::host::RealHost::new();
    let started = std::time::Instant::now();
    let found = collect(&host, &Scan::Off, &mut scan::Memo::default(), None);
    println!("{:?} in {:?}", found, started.elapsed());
    contract::assert_conforms("v1", "packages.request", &report_with(&found));
}

/// `cargo test cpu_on_this_host -- --ignored --nocapture`: the CPU time of the two passes that grow with
/// the host (dpkg's file lists for the services' executables, and the whole library scan).
#[test]
#[ignore = "reads the real host; run by hand"]
fn cpu_on_this_host() {
    fn cpu() -> std::time::Duration {
        // SAFETY: getrusage fills the zeroed struct it is given.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
        let t = |tv: libc::timeval| {
            std::time::Duration::from_secs(tv.tv_sec as u64)
                + std::time::Duration::from_micros(tv.tv_usec as u64)
        };
        t(usage.ru_utime) + t(usage.ru_stime)
    }
    let host = crate::facts::host::RealHost::new();
    let ctx = Ctx::new(&host, std::time::Duration::from_secs(60));
    let wanted: HashSet<String> = ["/usr/sbin/cron", "/usr/sbin/sshd", "/usr/bin/python3"]
        .map(String::from)
        .into();
    let (c, w) = (cpu(), std::time::Instant::now());
    let found = owners::owners(&ctx, &wanted).unwrap();
    println!(
        "owners: {} found, cpu {:?}, wall {:?}",
        found.len(),
        cpu() - c,
        w.elapsed()
    );
    // Without CAP_SYS_PTRACE (as here) only this process's maps are readable: list just it.
    struct OwnProcess(crate::facts::host::RealHost);
    impl Host for OwnProcess {
        fn stat(&self, p: &Path) -> io::Result<Stat> {
            self.0.stat(p)
        }
        fn read(&self, p: &Path, m: u64) -> io::Result<Vec<u8>> {
            self.0.read(p, m)
        }
        fn list(&self, d: &Path, m: usize) -> io::Result<Vec<String>> {
            if d == Path::new("/proc") {
                return Ok(vec![std::process::id().to_string()]);
            }
            self.0.list(d, m)
        }
        fn run(&self, c: &Command) -> Result<Vec<u8>, RunError> {
            self.0.run(c)
        }
        fn head(&self, p: &Path, n: usize) -> io::Result<Vec<u8>> {
            scan::ScanHost(self.0.clone()).head(p, n)
        }
        fn inspect(&self, p: &Path) -> io::Result<crate::facts::host::Inspect> {
            scan::ScanHost(self.0.clone()).inspect(p)
        }
        fn resolve(&self, p: &Path) -> io::Result<std::path::PathBuf> {
            scan::ScanHost(self.0.clone()).resolve(p)
        }
    }
    let host = OwnProcess(host);
    let (c, w) = (cpu(), std::time::Instant::now());
    match scan::scan(&host) {
        Ok(out) => println!(
            "scan: {} libraries, {} native, cpu {:?}, wall {:?}",
            out.libraries.len(),
            out.native.len(),
            cpu() - c,
            w.elapsed()
        ),
        Err(e) => println!("scan failed: {e}"),
    }
}
