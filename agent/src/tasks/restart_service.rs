//! The `restart_service` task (P3-A06, FR-3.3, AC-3.9, DEC-15, #36): `systemctl restart` of one
//! service unit this VM's owner allowed, then a check that it is active.
//!
//! **Checks, with nothing run** ([`TaskImpl::prepare`]), in this order, each a `refused` result:
//!
//! 1. `invalid_params`: the parameters are exactly `{"service": <string>}` and the string is a full
//!    service unit name as the catalog's pattern allows (letters, digits, `_ . @ -`, starting with a
//!    letter or digit, ending in `.service`, at most 256 characters), so it can never be an option, a
//!    path, or shell syntax ([`ValidatedArg::service_unit`]). A template instance
//!    (`postgresql@17-main.service`) is a full name and is allowed when listed exactly.
//! 2. `protected_service`: the name is protected (DEC-15, [`protected`]: the agent's own units, SSH,
//!    systemd's units, networking, D-Bus, and their template instances), **or** it names the same
//!    unit as a protected name through symbolic links in a systemd unit directory ([`UNIT_DIRS`]):
//!    the name is a link whose chain reaches a protected unit (`messagebus.service` pointing at
//!    `dbus.service`), or a link with a protected name leads to it (`ssh.service` pointing at
//!    `remote-shell.service`) ([`aliased_protected`]). There is no override (owner, 2026-11-08);
//!    listing such a name locally does not help. The alias check reads the file system only.
//! 3. `not_allowed_locally` (AC-3.9): the type is enabled and the exact name is in the local
//!    `[tasks] allowed_services` ([`TaskSettings::allows_restart_of`]). The server checks its own
//!    allowlist before it creates the task; the agent checks this one whatever the server says.
//!
//! The poller checks first that the type is in the catalog and enabled here (`not_enabled_locally`).
//!
//! **Run.** `/usr/bin/systemctl restart -- <unit>` under the catalog's `service_manager` privilege: a
//! child of the agent inside its sandbox, talking to systemd over its private socket
//! (`docs/operations/agent-task-privileges.md`). `systemctl restart` waits for the restart job, so
//! once it exits the unit has been started again or has failed to. After [`SETTLE`] (so a unit that
//! exits at once is caught), `systemctl is-active -- <unit>` is asked every [`RECHECK`] until it says
//! `active` or [`ACTIVE_WAIT`] passes (a unit may still be `activating`). If it never does,
//! `systemctl status` of the unit is added to the output for the operator.
//!
//! **Result.** `succeeded` when the restart exited 0 and the unit is active; `failed` with
//! `nonzero_exit` and the exit status of `systemctl restart` when it failed, or of the last
//! `systemctl is-active` (3: not active) when the unit did not come up. `details.unit_active` says
//! whether the unit was active at the end. The output is what systemctl printed.
//!
//! The catalog makes the type **not interruptible**: a cancel never stops it, the deadline (300 s)
//! does, and when the agent stops it gets [`super::executor::spawn::SHUTDOWN_WAIT`] to finish its
//! current program, and waits no longer between programs.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Map, Value};

use super::catalog::Privilege;
use super::executor::spawn::ValidatedArg;
use super::executor::{Exit, Finish, Job, Program, Run, Stop, TaskImpl, parse};
use super::ledger::Outcome;
use super::settings::{TaskSettings, protected};

/// The catalog type id.
pub const TYPE_ID: &str = "restart_service";

/// The service manager. One absolute path, fixed in the agent (`/bin` is `/usr/bin` on merged-`/usr`
/// systems, which Debian 12 and later and most current distributions are).
pub const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// systemd's system unit search path (`systemd.unit(5)`), where an alias is a symbolic link.
pub const UNIT_DIRS: &[&str] = &[
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/run/systemd/generator.early",
    "/etc/systemd/system",
    "/etc/systemd/system.attached",
    "/run/systemd/system",
    "/run/systemd/system.attached",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/generator.late",
];

/// How long after the restart the unit's state is first asked.
pub const SETTLE: Duration = Duration::from_secs(2);

/// How long the unit has, after [`SETTLE`], to become active.
pub const ACTIVE_WAIT: Duration = Duration::from_secs(15);

/// How often `systemctl is-active` is asked while the unit is not active yet.
pub const RECHECK: Duration = Duration::from_secs(1);

/// At most this many links of an alias chain are followed.
const MAX_LINKS: usize = 8;

/// The task type.
pub struct RestartService {
    systemctl: &'static str,
    unit_dirs: Vec<PathBuf>,
    settle: Duration,
    active_wait: Duration,
    recheck: Duration,
}

impl RestartService {
    /// The real service manager and unit directories.
    pub fn production() -> Self {
        Self {
            systemctl: SYSTEMCTL,
            unit_dirs: UNIT_DIRS.iter().map(PathBuf::from).collect(),
            settle: SETTLE,
            active_wait: ACTIVE_WAIT,
            recheck: RECHECK,
        }
    }
}

/// The catalog's parameters.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Params {
    service: String,
}

impl TaskImpl for RestartService {
    fn type_id(&self) -> &'static str {
        TYPE_ID
    }

    fn prepare(
        &self,
        parameters: &Value,
        settings: &TaskSettings,
    ) -> Result<Box<dyn Job>, &'static str> {
        let Params { service } = parse(parameters)?;
        let unit = ValidatedArg::service_unit(&service).ok_or("invalid_params")?;
        if protected(unit.as_str()).is_some()
            || aliased_protected(unit.as_str(), &self.unit_dirs).is_some()
        {
            return Err("protected_service");
        }
        if !settings.allows_restart_of(unit.as_str()) {
            return Err("not_allowed_locally");
        }
        Ok(Box::new(RestartJob {
            unit,
            systemctl: self.systemctl,
            settle: self.settle,
            active_wait: self.active_wait,
            recheck: self.recheck,
        }))
    }
}

/// Why `unit` shares a unit with a protected name, if it does, reading symbolic links in `dirs` only.
/// The unit's names are `unit` (and, for a template instance, its template) and every name their
/// links lead to; it is protected if any of them is, or if a link anywhere in `dirs` whose chain
/// reaches one of them has a protected name on its chain (`ssh.service -> remote-shell.service`
/// makes `remote-shell.service` the SSH server too; review of #169).
pub fn aliased_protected(unit: &str, dirs: &[PathBuf]) -> Option<&'static str> {
    let mut own = vec![unit.to_owned()];
    if let Some((base, instance)) = unit.split_once('@')
        && instance != ".service"
    {
        own.push(format!("{base}@.service"));
    }
    let mut group: BTreeSet<String> = own.iter().cloned().collect();
    for dir in dirs {
        for name in &own {
            group.extend(chain(&dir.join(name)));
        }
    }
    if let Some(why) = group.iter().find_map(|name| protected(name)) {
        return Some(why);
    }
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|t| t.is_symlink()) {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let links = chain(&entry.path());
            if links.iter().any(|link| group.contains(link))
                && let Some(why) = std::iter::once(&name)
                    .chain(&links)
                    .find_map(|n| protected(n))
            {
                return Some(why);
            }
        }
    }
    None
}

/// The names the symbolic links from `path` lead to, in order (at most [`MAX_LINKS`]).
fn chain(path: &Path) -> Vec<String> {
    let mut names = Vec::new();
    let mut path = path.to_owned();
    for _ in 0..MAX_LINKS {
        let Ok(target) = std::fs::read_link(&path) else {
            break;
        };
        let Some(name) = target.file_name().and_then(|n| n.to_str()) else {
            break;
        };
        names.push(name.to_owned());
        path = match path.parent() {
            Some(parent) if target.is_relative() => parent.join(&target),
            _ => target,
        };
    }
    names
}

struct RestartJob {
    unit: ValidatedArg,
    systemctl: &'static str,
    settle: Duration,
    active_wait: Duration,
    recheck: Duration,
}

impl RestartJob {
    fn systemctl(&self, args: &'static [&'static str]) -> Program {
        Program {
            path: self.systemctl,
            args,
            operand: Some(self.unit.clone()),
            privilege: Privilege::ServiceManager,
        }
    }

    /// Waits `wait`, or less if the agent is stopping; `Err` at the deadline.
    fn pause(run: &Run<'_>, wait: Duration) -> Result<(), Stop> {
        let until = Instant::now() + wait;
        while Instant::now() < until && !run.stopping() {
            if let Some(stop) = run.stopped() {
                return Err(stop);
            }
            thread::sleep(Duration::from_millis(50).min(until - Instant::now()));
        }
        Ok(())
    }
}

fn finish(outcome: Outcome, exit: Exit, active: bool) -> Finish {
    let mut details = Map::new();
    details.insert("unit_active".into(), Value::Bool(active));
    Finish {
        outcome,
        reason: (outcome != Outcome::Succeeded).then_some("nonzero_exit"),
        exit_status: exit.code,
        details,
    }
}

impl Job for RestartJob {
    fn run(&self, run: &mut Run<'_>) -> Result<Finish, Stop> {
        let restarted = run.program(&self.systemctl(&["restart"]))?;
        if !restarted.success() {
            run.note(&format!(
                "systemctl restart {} failed; its state now:",
                self.unit.as_str()
            ));
            let state = run.program(&self.systemctl(&["is-active"]))?;
            return Ok(finish(Outcome::Failed, restarted, state.success()));
        }
        Self::pause(run, self.settle)?;
        let until = Instant::now() + self.active_wait;
        let mut state = run.program(&self.systemctl(&["is-active"]))?;
        while !state.success() && Instant::now() < until && !run.stopping() {
            Self::pause(run, self.recheck)?;
            state = run.program(&self.systemctl(&["is-active"]))?;
        }
        if state.success() {
            run.note(&format!(
                "{} was restarted and is active",
                self.unit.as_str()
            ));
            return Ok(finish(Outcome::Succeeded, restarted, true));
        }
        run.note(&format!(
            "{} was restarted but is not active; its status:",
            self.unit.as_str()
        ));
        if !run.stopping() {
            run.program(&self.systemctl(&["status", "--no-pager", "--full", "--lines=20"]))?;
        }
        Ok(finish(Outcome::Failed, state, false))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use serde_json::json;

    use super::*;
    use crate::tasks::executor::tests::{TestControl, delivered, leak};
    use crate::tasks::executor::{Execution, Executor, Registry};
    use crate::test_support::TempDir;

    fn settings(text: &str) -> TaskSettings {
        let table: toml::Table = toml::from_str(text).unwrap();
        TaskSettings::from_value(table.get("tasks"))
    }

    fn allowing(services: &[&str]) -> TaskSettings {
        let list: Vec<String> = services.iter().map(|s| format!("\"{s}\"")).collect();
        settings(&format!(
            "[tasks]\nenabled = [\"restart_service\"]\nallowed_services = [{}]\n",
            list.join(", ")
        ))
    }

    /// A stand-in for systemctl (test code may run a shell): logs every call to `calls`, exits
    /// `restart_exit` for restart, and answers is-active from the `active` file.
    struct FakeSystemctl {
        dir: TempDir,
    }

    impl FakeSystemctl {
        fn new(restart_exit: i32) -> Self {
            let dir = TempDir::new();
            let log = dir.path("calls");
            let active = dir.path("active");
            let script = dir.path("systemctl");
            std::fs::write(
                &script,
                format!(
                    "#!/bin/sh\necho \"$*\" >> '{log}'\ncase \"$1\" in\n  restart) echo restarting; exit {restart_exit} ;;\n  is-active) if [ -f '{active}' ]; then echo active; exit 0; fi; echo activating; exit 3 ;;\n  status) echo '  Active: failed'; exit 3 ;;\nesac\nexit 1\n",
                    log = log.display(),
                    active = active.display(),
                ),
            )
            .unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            Self { dir }
        }

        fn set_active(&self, active: bool) {
            let path = self.dir.path("active");
            if active {
                std::fs::write(path, "").unwrap();
            } else {
                let _ = std::fs::remove_file(path);
            }
        }

        fn calls(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.path("calls"))
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        fn task(&self, unit_dirs: Vec<PathBuf>) -> RestartService {
            RestartService {
                systemctl: leak(self.dir.path("systemctl").display().to_string()),
                unit_dirs,
                settle: Duration::ZERO,
                active_wait: Duration::from_millis(300),
                recheck: Duration::from_millis(50),
            }
        }
    }

    fn registry(task: RestartService, settings: TaskSettings) -> Registry {
        Registry::new(
            vec![Box::new(task)],
            settings,
            // Never asked: a service_manager program runs as a child, not in a transient unit.
            Box::new(crate::tasks::executor::unit::Systemd),
        )
    }

    fn restart(service: &str) -> crate::tasks::executor::Delivered {
        delivered(TYPE_ID, json!({ "service": service }), 300)
    }

    fn run(registry: &Registry, service: &str) -> Execution {
        let task = restart(service);
        registry.check(&task).expect("passes its checks");
        registry.run(&task, &TestControl::default()).unwrap()
    }

    #[test]
    fn an_allowed_service_is_restarted_and_reported_active() {
        let systemctl = FakeSystemctl::new(0);
        systemctl.set_active(true);
        let registry = registry(systemctl.task(vec![]), allowing(&["nginx.service"]));
        let ran = run(&registry, "nginx.service");
        assert_eq!((ran.outcome, ran.reason), (Outcome::Succeeded, None));
        assert_eq!(ran.exit_status, Some(0));
        assert_eq!(Value::Object(ran.details), json!({"unit_active": true}));
        assert_eq!(
            systemctl.calls(),
            ["restart -- nginx.service", "is-active -- nginx.service"]
        );
        assert!(ran.output.contains("restarting\n"), "{}", ran.output);
        assert!(
            ran.output
                .contains("nginx.service was restarted and is active"),
            "{}",
            ran.output
        );
    }

    #[test]
    fn a_listed_template_instance_is_restarted_by_its_full_name() {
        let systemctl = FakeSystemctl::new(0);
        systemctl.set_active(true);
        let registry = registry(
            systemctl.task(vec![]),
            allowing(&["postgresql@17-main.service"]),
        );
        let ran = run(&registry, "postgresql@17-main.service");
        assert_eq!(ran.outcome, Outcome::Succeeded, "{}", ran.output);
        assert_eq!(
            systemctl.calls()[0],
            "restart -- postgresql@17-main.service"
        );
        // Another instance of the same template is not listed.
        assert_eq!(
            registry.check(&restart("postgresql@16-main.service")),
            Err("not_allowed_locally")
        );
    }

    #[test]
    fn a_failed_restart_is_nonzero_exit_with_the_units_state() {
        let systemctl = FakeSystemctl::new(5);
        let registry = registry(systemctl.task(vec![]), allowing(&["nginx.service"]));
        let ran = run(&registry, "nginx.service");
        assert_eq!(
            (ran.outcome, ran.reason, ran.exit_status),
            (Outcome::Failed, Some("nonzero_exit"), Some(5))
        );
        assert_eq!(ran.details["unit_active"], false);
        assert_eq!(
            systemctl.calls(),
            ["restart -- nginx.service", "is-active -- nginx.service"]
        );
    }

    #[test]
    fn a_unit_that_does_not_come_up_fails_with_its_status() {
        let systemctl = FakeSystemctl::new(0);
        let registry = registry(systemctl.task(vec![]), allowing(&["nginx.service"]));
        let ran = run(&registry, "nginx.service");
        assert_eq!(
            (ran.outcome, ran.reason, ran.exit_status),
            (Outcome::Failed, Some("nonzero_exit"), Some(3))
        );
        assert_eq!(ran.details["unit_active"], false);
        let calls = systemctl.calls();
        assert_eq!(calls.first().unwrap(), "restart -- nginx.service");
        assert!(calls.iter().filter(|c| c.starts_with("is-active")).count() >= 2);
        assert_eq!(
            calls.last().unwrap(),
            "status --no-pager --full --lines=20 -- nginx.service"
        );
        assert!(ran.output.contains("is not active"), "{}", ran.output);
        assert!(ran.output.contains("Active: failed"), "{}", ran.output);
    }

    #[test]
    fn a_unit_that_becomes_active_while_activating_succeeds() {
        let systemctl = FakeSystemctl::new(0);
        let registry = registry(systemctl.task(vec![]), allowing(&["nginx.service"]));
        let ran = thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(120));
                systemctl.set_active(true);
            });
            run(&registry, "nginx.service")
        });
        assert_eq!(ran.outcome, Outcome::Succeeded, "{}", ran.output);
        assert!(ran.output.contains("activating\n"), "{}", ran.output);
    }

    #[test]
    fn a_cancel_does_not_stop_a_restart() {
        // Not interruptible (catalog, DEC-14): the cancel is passed on as progress and ignored.
        let systemctl = FakeSystemctl::new(0);
        systemctl.set_active(true);
        let registry = registry(systemctl.task(vec![]), allowing(&["nginx.service"]));
        let control = TestControl::default();
        control.cancel.set(true);
        let ran = registry.run(&restart("nginx.service"), &control).unwrap();
        assert_eq!(ran.outcome, Outcome::Succeeded, "{}", ran.output);
        assert!(control.asked.get() > 0);
    }

    #[test]
    fn refused_names_run_nothing() {
        // P3-A06 AC, AC-3.9, threat model C4 and C5: the canary is the fake systemctl's call log.
        let systemctl = FakeSystemctl::new(0);
        let units = TempDir::new();
        let dir = units.path("system");
        std::fs::create_dir(&dir).unwrap();
        symlink(
            "/usr/lib/systemd/system/dbus.service",
            dir.join("messagebus.service"),
        )
        .unwrap();
        symlink("ssh.service", dir.join("remote-shell.service")).unwrap();
        symlink("hop.service", dir.join("chain.service")).unwrap();
        symlink("systemd-journald.service", dir.join("hop.service")).unwrap();
        symlink("sshd@.service", dir.join("console@.service")).unwrap();
        symlink("/dev/null", dir.join("masked.service")).unwrap();
        // Reverse aliases (review of #169): a protected name pointing at a listed, regular unit.
        std::fs::write(dir.join("remote-login.service"), "[Service]\n").unwrap();
        symlink("remote-login.service", dir.join("ssh.service")).unwrap();
        symlink("bus-relay.service", dir.join("dbus.service")).unwrap();
        symlink("bus-relay-real.service", dir.join("bus-relay.service")).unwrap();
        symlink("/somewhere/terminal@.service", dir.join("sshd@.service")).unwrap();
        // An unrelated link, and one that is not protected, change nothing.
        symlink("rsyslog.service", dir.join("syslog.service")).unwrap();
        let listed = [
            "nginx.service",
            "messagebus.service",
            "remote-shell.service",
            "chain.service",
            "console@tty1.service",
            "masked.service",
            "remote-login.service",
            "bus-relay-real.service",
            "terminal@tty2.service",
            "rsyslog.service",
        ];
        let registry = registry(systemctl.task(vec![dir]), allowing(&listed));
        let cases: &[(Value, &str)] = &[
            // Option-like or shell-like names, and malformed parameters.
            (json!({"service": "--now.service"}), "invalid_params"),
            (json!({"service": "-x.service"}), "invalid_params"),
            (
                json!({"service": "nginx.service; reboot"}),
                "invalid_params",
            ),
            (json!({"service": "$(reboot).service"}), "invalid_params"),
            (json!({"service": "`id`.service"}), "invalid_params"),
            (json!({"service": "a b.service"}), "invalid_params"),
            (json!({"service": "../nginx.service"}), "invalid_params"),
            (json!({"service": "/etc/nginx.service"}), "invalid_params"),
            (json!({"service": "nginx"}), "invalid_params"),
            (json!({"service": "nginx.socket"}), "invalid_params"),
            // Threat model C5: a glob, and other unit types.
            (json!({"service": "ssh*.service"}), "invalid_params"),
            (json!({"service": "reboot.target"}), "invalid_params"),
            (json!({"service": "ssh.socket"}), "invalid_params"),
            (json!({"service": "nginx.service\n"}), "invalid_params"),
            (json!({"service": ""}), "invalid_params"),
            (
                json!({"service": format!("{}.service", "a".repeat(249))}),
                "invalid_params",
            ),
            (json!({"service": ["nginx.service"]}), "invalid_params"),
            (
                json!({"service": "nginx.service", "force": true}),
                "invalid_params",
            ),
            (json!({}), "invalid_params"),
            (json!(null), "invalid_params"),
            // Protected, listed or not, with no override (DEC-15).
            (
                json!({"service": "fleet-agent.service"}),
                "protected_service",
            ),
            (
                json!({"service": "fleet-agent-update.service"}),
                "protected_service",
            ),
            (json!({"service": "ssh.service"}), "protected_service"),
            (json!({"service": "sshd@x.service"}), "protected_service"),
            (
                json!({"service": "systemd-journald.service"}),
                "protected_service",
            ),
            (json!({"service": "dbus.service"}), "protected_service"),
            (
                json!({"service": "networking.service"}),
                "protected_service",
            ),
            // Listed, but an alias of a protected unit.
            (
                json!({"service": "messagebus.service"}),
                "protected_service",
            ),
            (
                json!({"service": "remote-shell.service"}),
                "protected_service",
            ),
            (json!({"service": "chain.service"}), "protected_service"),
            (
                json!({"service": "console@tty1.service"}),
                "protected_service",
            ),
            // Listed, but a protected name is an alias of it.
            (
                json!({"service": "remote-login.service"}),
                "protected_service",
            ),
            (
                json!({"service": "bus-relay-real.service"}),
                "protected_service",
            ),
            (
                json!({"service": "terminal@tty2.service"}),
                "protected_service",
            ),
            // On the server's allowlist, maybe, but not on this VM's (AC-3.9).
            (
                json!({"service": "postgresql.service"}),
                "not_allowed_locally",
            ),
            (json!({"service": "NGINX.service"}), "not_allowed_locally"),
        ];
        for (parameters, want) in cases {
            let task = delivered(TYPE_ID, parameters.clone(), 300);
            assert_eq!(registry.check(&task), Err(*want), "{parameters}");
            // Even run directly, a task that fails its checks runs nothing.
            let ran = registry.run(&task, &TestControl::default()).unwrap();
            assert_eq!(ran.reason, Some("agent_error"), "{parameters}");
        }
        assert!(systemctl.calls().is_empty(), "{:?}", systemctl.calls());
        // A masked unit is not an alias of anything protected; the listed name passes.
        assert!(registry.check(&restart("masked.service")).is_ok());
        assert!(registry.check(&restart("nginx.service")).is_ok());
        assert!(registry.check(&restart("rsyslog.service")).is_ok());
        assert!(systemctl.calls().is_empty());
    }

    #[test]
    fn the_agents_own_unit_is_refused_by_default_and_when_enabled() {
        let task = || RestartService::production();
        let by_default = registry(task(), TaskSettings::default());
        for unit in ["fleet-agent.service", "nginx.service"] {
            // The poller refuses it `not_enabled_locally` first; the type's own check refuses too.
            assert!(by_default.check(&restart(unit)).is_err(), "{unit}");
        }
        assert_eq!(
            by_default.check(&restart("fleet-agent.service")),
            Err("protected_service")
        );
        let enabled = registry(task(), allowing(&["nginx.service"]));
        assert_eq!(
            enabled.check(&restart("fleet-agent.service")),
            Err("protected_service")
        );
        assert_eq!(
            enabled.check(&restart("cron.service")),
            Err("not_allowed_locally")
        );
    }

    /// The unit `scripts/task-privilege-smoke.sh` starts for this test: harmless (`sleep`), and not
    /// protected, unlike the framework's `fleet-agent-privsmoke-dummy.service`.
    const SMOKE_UNIT: &str = "cmdb-privsmoke-restart.service";

    fn invocation_of(unit: &str) -> String {
        let out = std::process::Command::new("/usr/bin/systemctl")
            .args(["show", "--property=InvocationID", "--value", unit])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    #[test]
    #[ignore = "needs root and systemd; run by scripts/task-privilege-smoke.sh"]
    fn privilege_smoke_restart_service_restarts_an_allowed_unit_from_inside_the_sandbox() {
        // P3-A06 AC: the real type, the real /usr/bin/systemctl, the real unit directories, under
        // every [Service] option of the agent's unit.
        let before = invocation_of(SMOKE_UNIT);
        assert_eq!(before.len(), 32, "{SMOKE_UNIT} is not running");
        let registry = registry(RestartService::production(), allowing(&[SMOKE_UNIT]));
        let ran = run(&registry, SMOKE_UNIT);
        assert_eq!(
            (ran.outcome, ran.reason),
            (Outcome::Succeeded, None),
            "{}",
            ran.output
        );
        assert_eq!(ran.details["unit_active"], true);
        assert!(ran.output.contains("active"), "{}", ran.output);
        assert_ne!(
            invocation_of(SMOKE_UNIT),
            before,
            "the unit was not restarted"
        );
        // The agent's own unit (here, the smoke test's own service) is refused with nothing run.
        let own = "fleet-agent-privsmoke.service";
        let own_before = invocation_of(own);
        assert_eq!(registry.check(&restart(own)), Err("protected_service"));
        assert_eq!(invocation_of(own), own_before);
    }

    #[test]
    #[ignore = "needs root and systemd; run by scripts/task-privilege-smoke.sh"]
    fn privilege_smoke_restart_service_reports_a_unit_that_does_not_exist() {
        let missing = "cmdb-privsmoke-missing.service";
        let registry = registry(RestartService::production(), allowing(&[missing]));
        let ran = run(&registry, missing);
        assert_eq!(
            (ran.outcome, ran.reason),
            (Outcome::Failed, Some("nonzero_exit")),
            "{}",
            ran.output
        );
        assert_eq!(ran.details["unit_active"], false);
    }

    #[test]
    fn the_production_type_uses_the_fixed_systemctl_and_systemds_search_path() {
        let task = RestartService::production();
        assert_eq!(task.systemctl, "/usr/bin/systemctl");
        assert!(
            task.unit_dirs
                .contains(&PathBuf::from("/etc/systemd/system"))
        );
        assert!(
            task.unit_dirs
                .contains(&PathBuf::from("/usr/lib/systemd/system"))
        );
        assert!(task.unit_dirs.iter().all(|d| d.is_absolute()));
    }
}
