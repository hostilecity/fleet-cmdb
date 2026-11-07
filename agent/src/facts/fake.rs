//! A fake [`Host`] for tests: files, directories, `stat` results, and command output served from
//! memory (mostly the Debian 13 fixtures in `tests/fixtures/facts/debian13/`), with a log of everything
//! the readers asked for. The log is how tests show that a reader only `stat`ed a sensitive file and
//! only ran its own fixed commands.

#![allow(dead_code)] // a builder with every knob, not every knob used yet

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::Path;
use std::sync::Mutex;

use serde_json::{Map, Value, json};

use super::host::{Command, Host, RunError, Stat};

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/facts/debian13/"
);

pub fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}{name}")).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

/// A file of `tests/fixtures/packages/debian13/` (P2-AGENT-PACKAGES).
pub fn package_fixture(name: &str) -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/packages/debian13/"
    );
    std::fs::read(format!("{path}{name}")).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

/// What a fake unit looks like to `systemctl show`: load state, active state, unit file state.
type Unit = (String, String, String);

#[derive(Default)]
pub struct FakeHost {
    files: HashMap<String, Vec<u8>>,
    stats: HashMap<String, Stat>,
    denied: HashSet<String>,
    broken: HashMap<String, io::ErrorKind>,
    dirs: HashMap<String, Vec<String>>,
    units: HashMap<String, Unit>,
    /// Command output by `"<program> <first argument>"`, for example `"sshd -T"`.
    outputs: HashMap<String, Result<Vec<u8>, RunError>>,
    log: Mutex<Vec<String>>,
}

impl FakeHost {
    /// A Debian 13 host with `unattended-upgrades` installed and switched on, `sshd` with its stock
    /// configuration, no firewall, the file permissions Debian ships, and the dpkg listing of
    /// `tests/fixtures/packages/debian13/` (30 installed packages).
    pub fn debian13() -> Self {
        let mut host = Self::default();
        host.files
            .insert("/etc/login.defs".into(), fixture("login.defs"));
        host.files.insert("/etc/passwd".into(), fixture("passwd"));
        host.files.insert("/etc/group".into(), fixture("group"));
        host.files.insert(
            "/etc/default/useradd".into(),
            b"# Default values for useradd(8)\nSHELL=/bin/sh\n# INACTIVE=-1\n".to_vec(),
        );
        host.files.insert(
            "/etc/security/pwquality.conf".into(),
            fixture("pwquality.conf"),
        );
        host.files.insert(
            "/etc/pam.d/common-password".into(),
            fixture("common-password"),
        );
        host.dirs
            .insert("/etc/security/pwquality.conf.d".into(), Vec::new());
        for (path, mode, group) in [
            ("/etc/passwd", 0o644, 0),
            ("/etc/passwd-", 0o644, 0),
            ("/etc/group", 0o644, 0),
            ("/etc/group-", 0o644, 0),
            ("/etc/shadow", 0o640, 42),
            ("/etc/shadow-", 0o640, 42),
            ("/etc/gshadow", 0o640, 42),
            ("/etc/gshadow-", 0o640, 42),
            ("/etc/ssh/sshd_config", 0o644, 0),
            ("/etc/sudoers", 0o440, 0),
            ("/etc/login.defs", 0o644, 0),
            ("/etc/fstab", 0o644, 0),
            ("/etc/crontab", 0o644, 0),
            ("/etc/cron.d", 0o755, 0),
            ("/etc/cron.hourly", 0o755, 0),
            ("/etc/cron.daily", 0o755, 0),
            ("/etc/cron.weekly", 0o755, 0),
            ("/etc/cron.monthly", 0o755, 0),
            ("/etc/issue", 0o644, 0),
            ("/etc/issue.net", 0o644, 0),
            ("/etc/motd", 0o644, 0),
            ("/usr/bin/unattended-upgrade", 0o755, 0),
            ("/var/lib/dpkg/status", 0o644, 0),
        ] {
            host.stats.insert(
                path.into(),
                Stat {
                    mode,
                    uid: 0,
                    gid: group,
                },
            );
        }
        for (name, load, active, file) in [
            ("ssh.service", "loaded", "active", "enabled"),
            ("cron.service", "loaded", "active", "enabled"),
            ("unattended-upgrades.service", "loaded", "active", "enabled"),
            ("rsyslog.service", "not-found", "inactive", ""),
            ("systemd-journald.service", "loaded", "active", "static"),
            ("systemd-timesyncd.service", "loaded", "active", "enabled"),
            ("apparmor.service", "loaded", "active", "enabled"),
            ("apt-daily.timer", "loaded", "active", "enabled"),
            ("apt-daily-upgrade.timer", "loaded", "active", "enabled"),
        ] {
            host.units
                .insert(name.into(), (load.into(), active.into(), file.into()));
        }
        host.outputs
            .insert("sshd -T".into(), Ok(fixture("sshd-T.stock")));
        host.outputs.insert(
            "apt-config dump".into(),
            Ok(fixture("apt-config-dump.auto")),
        );
        host.outputs.insert(
            "systemctl list-units".into(),
            Ok(fixture("systemctl-running")),
        );
        host.outputs.insert(
            "systemctl list-unit-files".into(),
            Ok(fixture("systemctl-enabled")),
        );
        host.outputs.insert(
            "dpkg-query --show".into(),
            Ok(package_fixture("dpkg-query-show")),
        );
        host
    }

    pub fn with_file(mut self, path: &str, contents: &[u8]) -> Self {
        self.files.insert(path.into(), contents.to_vec());
        self
    }

    pub fn without_file(mut self, path: &str) -> Self {
        self.files.remove(path);
        self.stats.remove(path);
        self
    }

    pub fn with_stat(mut self, path: &str, mode: u32, uid: u32, gid: u32) -> Self {
        self.stats.insert(path.into(), Stat { mode, uid, gid });
        self
    }

    /// Reading or `stat`ing `path` fails with permission denied.
    pub fn denying(mut self, path: &str) -> Self {
        self.denied.insert(path.into());
        self
    }

    /// Reading `path` fails with `kind`.
    pub fn breaking(mut self, path: &str, kind: io::ErrorKind) -> Self {
        self.broken.insert(path.into(), kind);
        self
    }

    pub fn with_dir(mut self, dir: &str, names: &[&str]) -> Self {
        self.dirs
            .insert(dir.into(), names.iter().map(|n| (*n).to_owned()).collect());
        self
    }

    pub fn with_unit(mut self, name: &str, load: &str, active: &str, file_state: &str) -> Self {
        self.units
            .insert(name.into(), (load.into(), active.into(), file_state.into()));
        self
    }

    pub fn with_output(mut self, key: &str, output: Result<Vec<u8>, RunError>) -> Self {
        self.outputs.insert(key.into(), output);
        self
    }

    pub fn without_output(mut self, key: &str) -> Self {
        self.outputs.remove(key);
        self
    }

    /// Everything the readers asked for, in order: `stat PATH`, `read PATH`, `list DIR`, `run LINE`.
    pub fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    fn record(&self, entry: String) {
        self.log.lock().unwrap().push(entry);
    }

    fn systemctl_show(&self, args: &[String]) -> Vec<u8> {
        let names: &[String] = match args.iter().position(|a| a == "--") {
            Some(at) => &args[at + 1..],
            None => &[],
        };
        let mut out = String::new();
        for name in names {
            let (load, active, file) = self
                .units
                .get(name)
                .cloned()
                .unwrap_or_else(|| ("not-found".into(), "inactive".into(), String::new()));
            out.push_str(&format!(
                "LoadState={load}\nActiveState={active}\nUnitFileState={file}\n\n"
            ));
        }
        out.into_bytes()
    }
}

impl Host for FakeHost {
    fn stat(&self, path: &Path) -> io::Result<Stat> {
        let path = path.to_string_lossy().into_owned();
        self.record(format!("stat {path}"));
        if self.denied.contains(&path) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if let Some(kind) = self.broken.get(&path) {
            return Err((*kind).into());
        }
        self.stats
            .get(&path)
            .copied()
            .or_else(|| {
                self.files.contains_key(&path).then_some(Stat {
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                })
            })
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }

    fn read(&self, path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
        let path = path.to_string_lossy().into_owned();
        self.record(format!("read {path}"));
        if self.denied.contains(&path) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        if let Some(kind) = self.broken.get(&path) {
            return Err((*kind).into());
        }
        let bytes = self
            .files
            .get(&path)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        if bytes.len() as u64 > max_bytes {
            return Err(io::Error::other(format!("larger than {max_bytes} bytes")));
        }
        Ok(bytes.clone())
    }

    fn list(&self, dir: &Path, max_entries: usize) -> io::Result<Vec<String>> {
        let dir = dir.to_string_lossy().into_owned();
        self.record(format!("list {dir}"));
        if self.denied.contains(&dir) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let names = self
            .dirs
            .get(&dir)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        if names.len() > max_entries {
            return Err(io::Error::other("too many entries"));
        }
        Ok(names.clone())
    }

    fn run(&self, command: &Command) -> Result<Vec<u8>, RunError> {
        self.record(format!("run {}", command.line()));
        let program = command.programs.first().copied().unwrap_or("");
        let base = program.rsplit('/').next().unwrap_or(program);
        let key = format!("{base} {}", command.args.first().map_or("", String::as_str));
        if let Some(output) = self.outputs.get(&key) {
            return output.clone();
        }
        match (base, command.args.first().map(String::as_str)) {
            ("systemctl", Some("show")) => Ok(self.systemctl_show(&command.args)),
            _ => Err(RunError::NotInstalled(command.programs.join(" or "))),
        }
    }
}

/// The server's manifest (`cmdb/config/fact_manifest.yml`) as the JSON `GET /api/v1/manifest/config`
/// publishes it, read without a YAML parser (the agent has none): the file is regular enough to read
/// line by line. A test that reads it fails if the server's manifest drifts from what the agent's
/// readers answer.
pub fn server_manifest() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cmdb/config/fact_manifest.yml"
    );
    let text = std::fs::read_to_string(path).expect("the server's fact manifest");
    let mut version = 0u64;
    let mut section = "";
    let mut entries: Vec<(String, Map<String, Value>)> = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("manifest_version:") {
            version = rest.trim().parse().unwrap();
        } else if matches!(line, "facts:" | "files:" | "services:") {
            section = line.trim_end_matches(':');
        } else if let Some(rest) = line.trim().strip_prefix("- ") {
            let (name, value) = rest.split_once(':').unwrap();
            let mut fields = Map::new();
            fields.insert(name.to_owned(), json!(value.trim().trim_matches('"')));
            entries.push((section.to_owned(), fields));
        } else if let Some((name, value)) = line.trim().split_once(':')
            && let Some((_, fields)) = entries.last_mut()
        {
            let value = value.trim();
            let parsed = match name {
                "since" | "max_length" | "max_items" | "item_max_length" | "minimum"
                | "maximum" => {
                    json!(value.parse::<i64>().unwrap())
                }
                "ordered" => json!(value == "true"),
                _ => json!(value.trim_matches('"')),
            };
            fields.insert(name.to_owned(), parsed);
        }
    }
    let facts: Vec<Value> = entries
        .into_iter()
        .map(|(section, fields)| {
            let get = |name: &str| fields.get(name).cloned();
            let (key, ty) = match section.as_str() {
                "files" => (
                    format!("file:{}", get("path").unwrap().as_str().unwrap()),
                    "file_attributes".to_owned(),
                ),
                "services" => (
                    format!("service:{}", get("unit").unwrap().as_str().unwrap()),
                    "service_state".to_owned(),
                ),
                _ => (
                    get("key").unwrap().as_str().unwrap().to_owned(),
                    get("type").unwrap().as_str().unwrap().to_owned(),
                ),
            };
            let mut fact = Map::new();
            fact.insert("key".into(), json!(key));
            fact.insert("type".into(), json!(ty));
            fact.insert("since".into(), get("since").unwrap());
            fact.insert("description".into(), json!("from the server's manifest"));
            // The server publishes each type's defaults for a limit the YAML does not state.
            let defaults: &[(&str, Value)] = match ty.as_str() {
                "string" => &[("max_length", json!(256))],
                "integer" => &[
                    ("minimum", json!(-9_007_199_254_740_991_i64)),
                    ("maximum", json!(9_007_199_254_740_991_i64)),
                ],
                "string_list" => &[
                    ("max_items", json!(200)),
                    ("item_max_length", json!(256)),
                    ("ordered", json!(false)),
                ],
                _ => &[],
            };
            for (name, default) in defaults {
                fact.insert((*name).into(), get(name).unwrap_or_else(|| default.clone()));
            }
            Value::Object(fact)
        })
        .collect();
    let mut facts = facts;
    facts.sort_by(|a, b| a["key"].as_str().cmp(&b["key"].as_str()));
    json!({"schema_version": 1, "manifest_version": version, "facts": facts})
}

/// [`server_manifest`], parsed as the agent parses a manifest.
pub fn server_manifest_parsed() -> super::manifest::Manifest {
    let manifest = super::manifest::parse(&server_manifest()).expect("a usable manifest");
    assert!(manifest.notes.is_empty(), "{:?}", manifest.notes);
    manifest
}
