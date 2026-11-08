//! The `[tasks]` section of the agent config: what this VM's owner allows tasks to do (FR-3.1,
//! FR-3.3, DEC-14, DEC-15, DEC-16, P3-A01).
//!
//! ```toml
//! [tasks]
//! # Task types this VM runs. Absent: only the types the catalog marks on by default, which is
//! # refresh_reports alone (DEC-14). `enabled = []` turns every task off.
//! enabled = ["refresh_reports", "restart_service", "apply_package_updates"]
//! # Services restart_service may restart, as full unit names. Empty by default (DEC-15).
//! allowed_services = ["nginx.service"]
//! ```
//!
//! `apply_package_updates` has no local setting beyond being enabled: DEC-16 fixes its policy and
//! gives it no parameters.
//!
//! The section is checked strictly, like the rest of the config: an unknown key, a wrong type, an
//! unknown task type, a malformed or protected service, or a repeated entry is an error. Unlike the
//! rest of the config, an error here does not stop the agent: it **fails safe**. No task type is
//! enabled, heartbeats and reports carry on, the agent logs the problem at startup and reports
//! `local_config: invalid` to the server, and `fleet-agent check-config` fails with the message.
//! Messages repeat a configured type id, which a credential pasted by mistake can never be (it always
//! has a `.`), and never any other configured value: a service is named by its position.

use std::collections::BTreeSet;

use serde::Deserialize;

use super::catalog::{Catalog, is_type_id};

/// The type that uses `allowed_services`.
pub const RESTART_SERVICE: &str = "restart_service";

/// At most this many entries in `allowed_services`.
pub const MAX_ALLOWED_SERVICES: usize = 64;

/// Longest unit name, as the catalog's `service` parameter allows (`maxLength`).
pub const MAX_SERVICE_NAME: usize = 256;

/// The validated `[tasks]` settings, or the fail-safe state after an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSettings {
    /// Enabled catalog type ids, sorted.
    enabled: Vec<String>,
    /// Allowed unit names, sorted.
    allowed_services: Vec<String>,
    /// Whether `enabled` was absent, so the catalog's defaults apply.
    default_types: bool,
    /// Why the section was refused; then nothing is enabled.
    problem: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTasks {
    enabled: Option<Vec<String>>,
    allowed_services: Option<Vec<String>>,
}

impl Default for TaskSettings {
    /// The settings with no `[tasks]` section.
    fn default() -> Self {
        Self::from_value(None)
    }
}

impl TaskSettings {
    /// The settings from the raw `[tasks]` value, checked against the embedded catalog.
    pub fn from_value(value: Option<&toml::Value>) -> Self {
        match Catalog::embedded() {
            Ok(catalog) => Self::from_value_with(value, catalog),
            Err(why) => Self::refused(format!(
                "the task catalog built into this agent cannot be used ({why}); no task can run. This is a defect in this agent build"
            )),
        }
    }

    pub(crate) fn from_value_with(value: Option<&toml::Value>, catalog: &Catalog) -> Self {
        match Self::validate(value, catalog) {
            Ok(settings) => settings,
            Err(problem) => Self::refused(format!(
                "{problem}. No task will run on this VM until the [tasks] section is fixed"
            )),
        }
    }

    fn refused(problem: String) -> Self {
        Self {
            enabled: Vec::new(),
            allowed_services: Vec::new(),
            default_types: false,
            problem: Some(problem),
        }
    }

    fn validate(value: Option<&toml::Value>, catalog: &Catalog) -> Result<Self, String> {
        let raw = match value {
            None => RawTasks {
                enabled: None,
                allowed_services: None,
            },
            Some(value) => value.clone().try_into::<RawTasks>().map_err(|e| {
                let message = e.message().trim_end().replace('\n', " ");
                format!(
                    "`tasks` is not valid: {}",
                    crate::config::redact_quoted_values(&message)
                )
            })?,
        };

        let default_types = raw.enabled.is_none();
        let enabled = match raw.enabled {
            None => catalog
                .tasks
                .iter()
                .filter(|t| t.on_by_default())
                .map(|t| t.id.clone())
                .collect(),
            Some(list) => {
                let mut seen = BTreeSet::new();
                for (index, id) in list.iter().enumerate() {
                    if !is_type_id(id) {
                        return Err(format!(
                            "`tasks.enabled` entry {} is not a task type id (lower-case letters, digits, and _); use one of {}",
                            index + 1,
                            catalog.ids().join(", ")
                        ));
                    }
                    if catalog.get(id).is_none() {
                        return Err(format!(
                            "`tasks.enabled` lists `{id}`, which is not a task type in this agent's catalog (version {}); use one of {}",
                            catalog.catalog_version,
                            catalog.ids().join(", ")
                        ));
                    }
                    if !seen.insert(id.clone()) {
                        return Err(format!("`tasks.enabled` lists `{id}` twice"));
                    }
                }
                seen.into_iter().collect()
            }
        };

        let services = raw.allowed_services.unwrap_or_default();
        if services.len() > MAX_ALLOWED_SERVICES {
            return Err(format!(
                "`tasks.allowed_services` has {} entries; at most {MAX_ALLOWED_SERVICES} are allowed",
                services.len()
            ));
        }
        let mut allowed = BTreeSet::new();
        for (index, name) in services.iter().enumerate() {
            if !is_service_unit(name) {
                return Err(format!(
                    "`tasks.allowed_services` entry {} is not a service unit name: use the full name, for example \"nginx.service\" (letters, digits, and _ . @ -, starting with a letter or digit, ending in .service, at most {MAX_SERVICE_NAME} characters)",
                    index + 1
                ));
            }
            if let Some(why) = protected(name) {
                return Err(format!(
                    "`tasks.allowed_services` entry {} is never restarted remotely ({why}, DEC-15); remove it",
                    index + 1
                ));
            }
            if !allowed.insert(name.clone()) {
                return Err(format!(
                    "`tasks.allowed_services` entry {} repeats an earlier entry",
                    index + 1
                ));
            }
        }

        Ok(Self {
            enabled,
            allowed_services: allowed.into_iter().collect(),
            default_types,
            problem: None,
        })
    }

    /// Whether the owner enabled task type `id` on this VM. Always `false` after an error.
    pub fn is_enabled(&self, id: &str) -> bool {
        self.enabled.iter().any(|e| e == id)
    }

    /// Whether `restart_service` may restart `unit` here: enabled, listed, and not protected
    /// (DEC-15). The server's own allowlist is checked separately (P3-A06).
    #[allow(dead_code)] // Used by the restart task (P3-A06).
    pub fn allows_restart_of(&self, unit: &str) -> bool {
        self.is_enabled(RESTART_SERVICE)
            && protected(unit).is_none()
            && self.allowed_services.iter().any(|s| s == unit)
    }

    /// Enabled type ids, sorted. Empty after an error.
    pub fn enabled(&self) -> &[String] {
        &self.enabled
    }

    /// Allowed unit names, sorted. Empty after an error.
    pub fn allowed_services(&self) -> &[String] {
        &self.allowed_services
    }

    /// Whether `tasks.enabled` was left out, so the catalog's defaults apply.
    pub fn uses_default_types(&self) -> bool {
        self.default_types
    }

    /// Why the `[tasks]` section was refused, if it was.
    pub fn problem(&self) -> Option<&str> {
        self.problem.as_deref()
    }

    /// Settings that are valid but probably not what the owner meant, for `check-config` and the
    /// startup log. `implemented` is what this agent version can run.
    pub fn remarks(&self, implemented: &[&str]) -> Vec<String> {
        let mut out = Vec::new();
        if self.problem.is_some() {
            return out;
        }
        let restart = self.is_enabled(RESTART_SERVICE);
        if restart && self.allowed_services.is_empty() {
            out.push(
                "restart_service is enabled but tasks.allowed_services is empty, so every restart is refused (DEC-15)"
                    .to_owned(),
            );
        }
        if !restart && !self.allowed_services.is_empty() {
            out.push(
                "tasks.allowed_services has no effect while restart_service is not in tasks.enabled"
                    .to_owned(),
            );
        }
        for id in &self.enabled {
            if !implemented.contains(&id.as_str()) {
                out.push(format!(
                    "this agent version cannot run {id} yet; the server is told so and does not offer it"
                ));
            }
        }
        out
    }
}

/// A full systemd service unit name, as the catalog's `service` parameter pattern allows:
/// `^[A-Za-z0-9][A-Za-z0-9_.@-]{0,247}\.service$`. The tests check this against the pattern in the
/// catalog itself.
pub fn is_service_unit(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".service") else {
        return false;
    };
    let mut chars = stem.chars();
    name.len() <= MAX_SERVICE_NAME
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-'))
}

/// Why `unit` is protected (DEC-15), if it is: refused even when listed. The agent's own units,
/// the SSH server, systemd's own units, networking, and D-Bus. A template instance
/// (`sshd@x.service`) counts as its template; `fleet-agent*` and `systemd-*` match by prefix.
pub fn protected(unit: &str) -> Option<&'static str> {
    let stem = unit.strip_suffix(".service").unwrap_or(unit);
    let base = stem.split_once('@').map_or(stem, |(base, _)| base);
    if base.starts_with("fleet-agent") {
        Some("it is this agent's own unit")
    } else if base == "systemd" || base.starts_with("systemd-") {
        Some("it is part of systemd")
    } else {
        match base {
            "ssh" | "sshd" => Some("it is the SSH server"),
            "networking" | "NetworkManager" => Some("it runs networking"),
            "dbus" | "dbus-broker" => Some("it is D-Bus"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(text: &str) -> TaskSettings {
        let table: toml::Table = toml::from_str(text).unwrap();
        TaskSettings::from_value(table.get("tasks"))
    }

    fn problem(text: &str) -> String {
        let s = settings(text);
        assert!(
            s.enabled().is_empty() && s.allowed_services().is_empty(),
            "{s:?}"
        );
        s.problem()
            .unwrap_or_else(|| panic!("accepted: {text}"))
            .to_owned()
    }

    #[test]
    fn by_default_only_refresh_reports_is_enabled() {
        // P3-A01 acceptance: with the default configuration the risky types are off (DEC-14).
        for s in [
            TaskSettings::default(),
            settings("[tasks]\n"),
            settings("[tasks]\nallowed_services = []\n"),
        ] {
            assert_eq!(s.problem(), None);
            assert_eq!(s.enabled(), ["refresh_reports"]);
            assert!(s.uses_default_types());
            assert!(!s.is_enabled("apply_package_updates"));
            assert!(!s.is_enabled("restart_service"));
            assert!(s.allowed_services().is_empty());
            assert!(!s.allows_restart_of("nginx.service"));
        }
    }

    #[test]
    fn the_owner_enables_types_and_services() {
        let s = settings(
            "[tasks]\nenabled = [\"restart_service\", \"apply_package_updates\", \"refresh_reports\"]\nallowed_services = [\"nginx.service\", \"app@blue.service\"]\n",
        );
        assert_eq!(s.problem(), None);
        assert!(!s.uses_default_types());
        assert_eq!(
            s.enabled(),
            [
                "apply_package_updates",
                "refresh_reports",
                "restart_service"
            ]
        );
        assert_eq!(s.allowed_services(), ["app@blue.service", "nginx.service"]);
        assert!(s.allows_restart_of("nginx.service"));
        assert!(!s.allows_restart_of("nginx"));
        assert!(!s.allows_restart_of("postgresql.service"));
    }

    #[test]
    fn an_empty_list_turns_every_task_off() {
        let s = settings("[tasks]\nenabled = []\n");
        assert_eq!(s.problem(), None);
        assert!(s.enabled().is_empty());
        assert!(!s.is_enabled("refresh_reports"));
    }

    #[test]
    fn a_listed_service_needs_restart_service_enabled() {
        let s = settings("[tasks]\nallowed_services = [\"nginx.service\"]\n");
        assert!(!s.allows_restart_of("nginx.service"));
        assert_eq!(
            s.remarks(&[]),
            [
                "tasks.allowed_services has no effect while restart_service is not in tasks.enabled",
                "this agent version cannot run refresh_reports yet; the server is told so and does not offer it",
            ]
        );
        assert!(s.remarks(&["refresh_reports"]).len() == 1);
        let s = settings("[tasks]\nenabled = [\"restart_service\"]\n");
        assert!(s.remarks(&["restart_service"])[0].contains("every restart is refused"));
    }

    #[test]
    fn unknown_types_fail_safe_with_a_message_naming_the_choices() {
        let message = problem("[tasks]\nenabled = [\"refresh_reports\", \"reboot\"]\n");
        assert!(message.contains("lists `reboot`"), "{message}");
        assert!(
            message.contains("apply_package_updates, refresh_reports, restart_service"),
            "{message}"
        );
        assert!(message.contains("No task will run"), "{message}");
    }

    #[test]
    fn every_other_mistake_fails_safe_too() {
        for (text, expected) in [
            (
                "[tasks]\nenable = [\"refresh_reports\"]\n",
                "unknown field `enable`",
            ),
            (
                "[tasks]\nenabled = \"refresh_reports\"\n",
                "`tasks` is not valid",
            ),
            ("[tasks]\nenabled = [1]\n", "`tasks` is not valid"),
            ("tasks = 1\n", "`tasks` is not valid"),
            (
                "[tasks]\nenabled = [\"Restart-Service\"]\n",
                "entry 1 is not a task type id",
            ),
            (
                "[tasks]\nenabled = [\"refresh_reports\", \"refresh_reports\"]\n",
                "`refresh_reports` twice",
            ),
            (
                "[tasks]\nallowed_services = [\"nginx\"]\n",
                "entry 1 is not a service unit name",
            ),
            (
                "[tasks]\nallowed_services = [\"-nginx.service\"]\n",
                "entry 1",
            ),
            ("[tasks]\nallowed_services = [\"a b.service\"]\n", "entry 1"),
            (
                "[tasks]\nallowed_services = [\"../x.service\"]\n",
                "entry 1",
            ),
            (
                "[tasks]\nallowed_services = [\"x.service;reboot\"]\n",
                "entry 1",
            ),
            (
                "[tasks]\nallowed_services = [\"a.service\", \"a.service\"]\n",
                "entry 2 repeats an earlier entry",
            ),
        ] {
            let message = problem(text);
            assert!(message.contains(expected), "{text}: {message}");
        }
        let many: Vec<String> = (0..=MAX_ALLOWED_SERVICES)
            .map(|i| format!("\"s{i}.service\""))
            .collect();
        let message = problem(&format!(
            "[tasks]\nallowed_services = [{}]\n",
            many.join(", ")
        ));
        assert!(message.contains("at most 64"), "{message}");
    }

    #[test]
    fn protected_services_are_refused_even_when_listed() {
        // DEC-15: the agent's own unit, SSH, systemd, networking, and D-Bus.
        for unit in [
            "fleet-agent.service",
            "fleet-agent-rollback.service",
            "ssh.service",
            "sshd.service",
            "sshd@1-192.0.2.1-198.51.100.7.service",
            "systemd-journald.service",
            "systemd-networkd.service",
            "systemd-udevd.service",
            "networking.service",
            "NetworkManager.service",
            "dbus.service",
            "dbus-broker.service",
        ] {
            assert!(protected(unit).is_some(), "{unit}");
            let message = problem(&format!(
                "[tasks]\nenabled = [\"restart_service\"]\nallowed_services = [\"{unit}\"]\n"
            ));
            assert!(message.contains("never restarted remotely"), "{message}");
        }
        for unit in [
            "nginx.service",
            "sshguard.service",
            "postgresql@17-main.service",
        ] {
            assert_eq!(protected(unit), None, "{unit}");
        }
    }

    #[test]
    fn a_pasted_credential_is_never_repeated() {
        let credential = crate::config::tests::CREDENTIAL;
        for text in [
            format!("[tasks]\nenabled = [\"{credential}\"]\n"),
            format!("[tasks]\nallowed_services = [\"{credential}\"]\n"),
            format!(
                "[tasks]\nallowed_services = [\"{credential}.service\", \"{credential}.service\"]\n"
            ),
            format!("[tasks]\nenabled = \"{credential}\"\n"),
            format!("[tasks]\nsecret = \"{credential}\"\n"),
        ] {
            let message = problem(&text);
            assert!(!message.contains("EXAMPLEkey01"), "{message}");
        }
    }

    /// Checks [`is_service_unit`] against the `service` parameter schema in the compiled-in
    /// catalog, so a change to the catalog's pattern or length fails here until the agent follows.
    fn catalog_accepts(name: &str) -> bool {
        let catalog = Catalog::embedded().unwrap();
        let schema = &catalog.get(RESTART_SERVICE).unwrap().parameters["properties"]["service"];
        jsonschema::draft202012::new(schema)
            .unwrap()
            .is_valid(&serde_json::json!(name))
    }

    #[test]
    fn service_unit_names_follow_the_catalog() {
        for good in [
            "nginx.service",
            "a.service",
            "getty@tty1.service",
            "postgresql@17-main.service",
            "a_b.c-d.service",
            &format!("{}.service", "a".repeat(248)),
        ] {
            assert!(is_service_unit(good), "{good}");
            assert!(catalog_accepts(good), "{good}");
        }
        for bad in [
            "",
            ".service",
            "nginx",
            "nginx.socket",
            "-a.service",
            "_a.service",
            "a b.service",
            "a/b.service",
            "a+b.service",
            "a\\x2d.service",
            "ä.service",
            &format!("{}.service", "a".repeat(249)),
            "nginx.service\n",
            "a..service",
        ] {
            assert_eq!(is_service_unit(bad), catalog_accepts(bad), "{bad}");
            if !["a..service"].contains(&bad) {
                assert!(!is_service_unit(bad), "{bad}");
            }
        }
        assert_eq!(
            catalog_accepts(&format!("{}.service", "a".repeat(248))),
            is_service_unit(&format!("{}.service", "a".repeat(248)))
        );
    }
}
