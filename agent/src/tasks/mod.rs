//! Remote tasks (Phase 3, FR-3.1, FR-3.3): the compiled-in catalog, the owner's local settings, and
//! the capabilities the agent reports to the server (P3-A01).
//!
//! - [`catalog`]: the shared task catalog, compiled in. The agent never takes a task definition
//!   from the server.
//! - [`settings`]: the `[tasks]` section of the config. Only `refresh_reports` is on by default;
//!   `restart_service` and `apply_package_updates` need a local edit (DEC-14), and restarts need the
//!   unit in the local allowlist (DEC-15). A bad section turns every task off.
//! - [`Capabilities`]: sent in every heartbeat as `tasks`, so the server offers a host only the
//!   types it both supports and has enabled (FR-3.1), and a restart only of a service its local
//!   allowlist names (owner, P3-D01 Q7).
//!
//! - [`poller`] and [`ledger`]: polling, the durable record of every task's steps, refusals, recovery
//!   after a crash, and result reporting (P3-A02). [`wire`] is the task API's JSON.
//! - [`executor`]: P3-A03's executor and P3-A05's privilege model: the registry of task types, strict
//!   checks, and the one way a task runs a program (fixed argument vector, no shell, clean
//!   environment, process group, deadline, bounded output, transient units for package managers).
//!
//! No task type is implemented yet (P3-A04, P3-A06, P3-AGENT-UPDATES): [`IMPLEMENTED`] is empty, so this agent reports
//! that it supports no task type, the server offers it none, and the poller does not poll.

pub mod catalog;
// The executor's task-facing API (`Run`, `Program`, `parse`, `Finish`, ...) is used by the task types,
// which come in P3-A04, P3-A06, and P3-AGENT-UPDATES, and by the tests; this build registers none (`IMPLEMENTED`).
#[allow(dead_code)]
pub mod executor;
pub mod ledger;
pub mod poller;
pub mod settings;
pub mod wire;

use serde::Serialize;

use catalog::Catalog;
use settings::TaskSettings;

/// The task types this agent version has an implementation for: exactly the types in
/// [`executor::Registry::production`] (checked by the tests), each in the catalog. Empty until the
/// tasks are built (P3-A04, P3-A06, P3-AGENT-UPDATES).
pub const IMPLEMENTED: &[&str] = &[];

/// `tasks` in `heartbeat.request` (docs/api/schemas/v1): what this host can run, and what its owner
/// allowed. The server offers a type only when it is in both `supported` and `enabled`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    /// The `catalog_version` compiled into this agent.
    pub catalog_version: u32,
    /// Catalog types this agent version can run, sorted.
    pub supported: Vec<String>,
    /// Catalog types the local configuration enables, sorted; empty when it is invalid.
    pub enabled: Vec<String>,
    /// The local restart allowlist (`[tasks] allowed_services`), sorted; empty when the
    /// configuration is invalid. The agent still checks it when a task arrives (AC-3.9).
    pub allowed_services: Vec<String>,
    /// `valid`, or `invalid` when the `[tasks]` section was refused and nothing is enabled.
    pub local_config: &'static str,
}

impl Capabilities {
    /// The capabilities for `settings` with the embedded catalog, or `None` if the catalog cannot
    /// be used: then the heartbeat carries no `tasks` and the server offers nothing.
    pub fn of(settings: &TaskSettings) -> Option<Self> {
        let catalog = Catalog::embedded().ok()?;
        Some(Self::with(settings, catalog, IMPLEMENTED))
    }

    pub(crate) fn with(settings: &TaskSettings, catalog: &Catalog, implemented: &[&str]) -> Self {
        let mut supported: Vec<String> = implemented
            .iter()
            .filter(|id| catalog.get(id).is_some())
            .map(|id| (*id).to_owned())
            .collect();
        supported.sort_unstable();
        supported.dedup();
        Self {
            catalog_version: catalog.catalog_version,
            supported,
            enabled: settings.enabled().to_vec(),
            allowed_services: settings.allowed_services().to_vec(),
            local_config: if settings.problem().is_some() {
                "invalid"
            } else {
                "valid"
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::contract::assert_conforms;

    fn settings(text: &str) -> TaskSettings {
        let table: toml::Table = toml::from_str(text).unwrap();
        TaskSettings::from_value(table.get("tasks"))
    }

    #[test]
    fn every_implemented_type_is_in_the_catalog_and_the_registry() {
        let catalog = Catalog::embedded().unwrap();
        for id in IMPLEMENTED {
            assert!(catalog.get(id).is_some(), "{id} is not in the catalog");
        }
        let registry = executor::Registry::production(TaskSettings::default());
        let mut implemented = IMPLEMENTED.to_vec();
        implemented.sort_unstable();
        assert_eq!(registry.ids(), implemented);
    }

    #[test]
    fn capabilities_report_the_catalog_version_and_the_local_choice() {
        let catalog = Catalog::embedded().unwrap();
        let caps = Capabilities::of(&TaskSettings::default()).unwrap();
        assert_eq!(caps.catalog_version, catalog.catalog_version);
        assert_eq!(caps.supported, IMPLEMENTED);
        assert_eq!(caps.enabled, ["refresh_reports"]);
        assert_eq!(caps.local_config, "valid");

        assert!(caps.allowed_services.is_empty());

        // The local restart allowlist is reported, sorted, so the server can leave out hosts that
        // would refuse (P3-D01 Q7).
        let listed = Capabilities::of(&settings(
            "[tasks]\nenabled = [\"restart_service\"]\nallowed_services = [\"nginx.service\", \"cron.service\"]\n",
        ))
        .unwrap();
        assert_eq!(listed.allowed_services, ["cron.service", "nginx.service"]);

        let invalid = Capabilities::of(&settings(
            "[tasks]\nenabled = [\"reboot\"]\nallowed_services = [\"nginx.service\"]\n",
        ))
        .unwrap();
        assert!(invalid.enabled.is_empty());
        assert!(invalid.allowed_services.is_empty());
        assert_eq!(invalid.local_config, "invalid");

        // Only catalog types count as supported, sorted and once each.
        let caps = Capabilities::with(
            &settings("[tasks]\nenabled = [\"restart_service\", \"refresh_reports\"]\n"),
            catalog,
            &[
                "restart_service",
                "unknown_type",
                "refresh_reports",
                "restart_service",
            ],
        );
        assert_eq!(caps.supported, ["refresh_reports", "restart_service"]);
        assert_eq!(caps.enabled, ["refresh_reports", "restart_service"]);
    }

    #[test]
    fn capabilities_conform_to_the_heartbeat_contract() {
        let catalog = Catalog::embedded().unwrap();
        for caps in [
            Capabilities::of(&TaskSettings::default()).unwrap(),
            Capabilities::of(&settings("[tasks]\nenabled = 1\n")).unwrap(),
            Capabilities::with(
                &settings(
                    "[tasks]\nenabled = [\"refresh_reports\", \"restart_service\", \"apply_package_updates\"]\nallowed_services = [\"nginx.service\", \"postgresql@17-main.service\"]\n",
                ),
                catalog,
                &catalog.ids(),
            ),
        ] {
            let heartbeat = serde_json::json!({
                "schema_version": 1,
                "agent_version": crate::AGENT_VERSION,
                "hostname": "vm-01.example.lan",
                "uptime_seconds": 5,
                "agent_time": "2026-01-01T12:00:00Z",
                "tasks": caps,
            });
            assert_conforms("v1", "heartbeat.request", &heartbeat);
        }
    }
}
