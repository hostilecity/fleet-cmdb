//! The task catalog compiled into the agent (FR-3.1, P3-S01, P3-A01).
//!
//! The shared catalog, `docs/api/tasks/task-catalog.json`, is compiled in with `include_str!`
//! straight from that file, so there is no second copy to drift and the agent never takes a task
//! definition from the server (or from anywhere else at runtime). The server reads the same file at
//! boot. `tests/contract.rs` checks that this is the file compiled in, and that it passes the
//! catalog's schema; the server's contract spec checks that no other copy exists.
//!
//! The text is parsed and checked once, on first use ([`Catalog::embedded`]). The tests parse it
//! too, so a catalog this agent cannot read fails CI rather than a host. If it ever failed on a host
//! anyway, the agent would run no task at all: every caller treats the error as "nothing supported".

use std::collections::BTreeSet;
use std::sync::OnceLock;

use serde::Deserialize;

/// The shared catalog, as compiled in: `docs/api/tasks/task-catalog.json`.
pub const EMBEDDED: &str = include_str!("../../../docs/api/tasks/task-catalog.json");

/// The only catalog file format this agent reads (`format_version`).
pub const FORMAT_VERSION: u32 = 1;

/// What a task type needs on the VM (FR-3.3, `privilege` in the catalog).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Privilege {
    /// Reads system state and writes nothing outside the agent's own state.
    ReadOnly,
    /// Asks systemd to restart units.
    ServiceManager,
    /// Installs and upgrades packages.
    PackageManager,
}

/// One catalog entry. Every field of the file is read, and an unknown one is an error, so the
/// agent's view of an entry cannot silently fall behind the file's.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskType {
    /// The stable type id, for example `restart_service`.
    #[serde(rename = "type")]
    pub id: String,
    #[allow(dead_code)] // Read by the executor and the tasks (P3-A03 onwards).
    pub name: String,
    #[allow(dead_code)] // Read by the executor and the tasks (P3-A03 onwards).
    pub description: String,
    /// The catalog version that added this type.
    pub since: u32,
    pub privilege: Privilege,
    /// Whether a cancel or the agent's shutdown may stop a running task of this type (DEC-14).
    pub interruptible: bool,
    /// Whether an agent runs this type without a local configuration change (DEC-14). The agent
    /// honours it only for [`Privilege::ReadOnly`] types, whatever the file says.
    pub enabled_by_default: bool,
    pub timeout_seconds: u64,
    #[allow(dead_code)] // Read by the executor and the tasks (P3-A03 onwards).
    pub expiry_seconds: u64,
    /// The closed JSON Schema of the parameters. The agent validates parameters with its own typed
    /// structs (P3-A03); the tests check those against this schema.
    pub parameters: serde_json::Value,
}

impl TaskType {
    /// Whether the type is on when the local configuration does not list `tasks.enabled` (DEC-14).
    pub fn on_by_default(&self) -> bool {
        self.enabled_by_default && self.privilege == Privilege::ReadOnly
    }
}

/// The parsed, checked catalog.
#[derive(Debug, Clone)]
pub struct Catalog {
    pub catalog_version: u32,
    /// In file order.
    pub tasks: Vec<TaskType>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCatalog {
    format_version: u32,
    catalog_version: u32,
    tasks: Vec<TaskType>,
}

impl Catalog {
    /// The compiled-in catalog, parsed on first use. An error says why it cannot be used; the agent
    /// then supports and runs no task.
    pub fn embedded() -> Result<&'static Catalog, &'static str> {
        static PARSED: OnceLock<Result<Catalog, String>> = OnceLock::new();
        PARSED
            .get_or_init(|| Catalog::parse(EMBEDDED))
            .as_ref()
            .map_err(String::as_str)
    }

    /// Parses catalog text and checks what the agent relies on. The full lint (closed parameter
    /// schemas, no command-like parameters) is the shared one in P3-S01; these checks are the ones
    /// whose failure would make this agent misread the file.
    pub fn parse(text: &str) -> Result<Catalog, String> {
        let raw: RawCatalog = serde_json::from_str(text)
            .map_err(|e| format!("the task catalog is not readable: {e}"))?;
        if raw.format_version != FORMAT_VERSION {
            return Err(format!(
                "the task catalog has format_version {}, but this agent reads only {FORMAT_VERSION}",
                raw.format_version
            ));
        }
        if raw.catalog_version == 0 {
            return Err("the task catalog's catalog_version must be at least 1".into());
        }
        if raw.tasks.is_empty() {
            return Err("the task catalog lists no task type".into());
        }
        let mut seen = BTreeSet::new();
        for task in &raw.tasks {
            if !is_type_id(&task.id) {
                return Err(format!(
                    "the task catalog has a type id that is not lower-case letters, digits, and _ (at most 64): {}",
                    crate::logging::sanitize(&task.id, 64)
                ));
            }
            if !seen.insert(task.id.as_str()) {
                return Err(format!("the task catalog lists `{}` twice", task.id));
            }
            if task.since == 0 || task.since > raw.catalog_version {
                return Err(format!(
                    "task type `{}` has since {}, outside 1..={} (the catalog_version)",
                    task.id, task.since, raw.catalog_version
                ));
            }
            if task.enabled_by_default && task.privilege != Privilege::ReadOnly {
                return Err(format!(
                    "task type `{}` is enabled_by_default but not read_only; only read-only types may be on by default (DEC-14)",
                    task.id
                ));
            }
            if !(1..=86_400).contains(&task.timeout_seconds) {
                return Err(format!(
                    "task type `{}` has timeout_seconds {}, outside 1..=86400",
                    task.id, task.timeout_seconds
                ));
            }
            if task.parameters.get("additionalProperties") != Some(&serde_json::Value::Bool(false))
            {
                return Err(format!(
                    "task type `{}` has a parameter schema that is not closed (additionalProperties must be false)",
                    task.id
                ));
            }
        }
        if raw.tasks.iter().map(|t| t.since).max() != Some(raw.catalog_version) {
            return Err(format!(
                "no task type has since {}, the catalog_version; a new version must add or change a type",
                raw.catalog_version
            ));
        }
        Ok(Catalog {
            catalog_version: raw.catalog_version,
            tasks: raw.tasks,
        })
    }

    /// The entry for `id`, if the catalog has it.
    pub fn get(&self, id: &str) -> Option<&TaskType> {
        self.tasks.iter().find(|t| t.id == id)
    }

    /// Every type id, sorted.
    pub fn ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self.tasks.iter().map(|t| t.id.as_str()).collect();
        ids.sort_unstable();
        ids
    }
}

/// A task type id as the catalog schema allows it: `^[a-z][a-z0-9_]{0,63}$`. Such a value can be
/// repeated in a message: it cannot be a credential, which always contains a `.`.
pub fn is_type_id(value: &str) -> bool {
    let mut chars = value.chars();
    value.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(id: &str) -> serde_json::Value {
        json!({
            "type": id,
            "name": "Example",
            "description": "Does nothing.",
            "since": 1,
            "privilege": "read_only",
            "interruptible": true,
            "enabled_by_default": false,
            "timeout_seconds": 60,
            "expiry_seconds": 86400,
            "parameters": {"type": "object", "additionalProperties": false, "properties": {}, "required": []}
        })
    }

    fn catalog_with(tasks: Vec<serde_json::Value>) -> serde_json::Value {
        json!({"format_version": 1, "catalog_version": 1, "tasks": tasks})
    }

    fn parse(value: &serde_json::Value) -> Result<Catalog, String> {
        Catalog::parse(&value.to_string())
    }

    #[test]
    fn the_embedded_catalog_is_the_shared_file_byte_for_byte() {
        // P3-A01: the build-time check that the binary's catalog is the server's.
        let shared = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../docs/api/tasks/task-catalog.json");
        assert_eq!(
            EMBEDDED.as_bytes(),
            std::fs::read(shared).unwrap().as_slice()
        );
    }

    #[test]
    fn the_embedded_catalog_parses_and_has_the_initial_types() {
        let catalog = Catalog::embedded().expect("the compiled-in catalog is valid");
        assert!(catalog.catalog_version >= 1);
        // P3-S01: the initial entries.
        for id in [
            "refresh_reports",
            "restart_service",
            "apply_package_updates",
        ] {
            assert!(catalog.get(id).is_some(), "{id} missing");
        }
    }

    #[test]
    fn only_read_only_types_are_on_by_default() {
        // DEC-14 and P3-A01's first acceptance criterion.
        let catalog = Catalog::embedded().unwrap();
        let on: Vec<&str> = catalog
            .tasks
            .iter()
            .filter(|t| t.on_by_default())
            .map(|t| t.id.as_str())
            .collect();
        assert_eq!(on, ["refresh_reports"]);
        let mut risky = catalog.get("restart_service").unwrap().clone();
        risky.enabled_by_default = true;
        assert!(
            !risky.on_by_default(),
            "a privileged type is never on by default"
        );
    }

    #[test]
    fn a_valid_minimal_catalog_parses() {
        let catalog = parse(&catalog_with(vec![entry("example")])).unwrap();
        assert_eq!(catalog.catalog_version, 1);
        assert_eq!(catalog.ids(), ["example"]);
        assert!(catalog.get("other").is_none());
    }

    #[test]
    fn catalogs_the_agent_would_misread_are_refused() {
        let cases: Vec<(serde_json::Value, &str)> = vec![
            (json!("not an object"), "not readable"),
            (
                json!({"format_version": 2, "catalog_version": 1, "tasks": [entry("a")]}),
                "format_version 2",
            ),
            (
                json!({"format_version": 1, "catalog_version": 0, "tasks": [entry("a")]}),
                "at least 1",
            ),
            (catalog_with(vec![]), "no task type"),
            (catalog_with(vec![entry("Bad-Id")]), "type id"),
            (catalog_with(vec![entry("a"), entry("a")]), "twice"),
            (
                json!({"format_version": 1, "catalog_version": 2, "tasks": [entry("a")]}),
                "no task type has since 2",
            ),
            (
                {
                    let mut c = catalog_with(vec![entry("a")]);
                    c["unexpected"] = json!(1);
                    c
                },
                "unknown field",
            ),
        ];
        for (value, expected) in cases {
            let error = parse(&value).unwrap_err();
            assert!(error.contains(expected), "{expected}: {error}");
        }

        let mut since = entry("a");
        since["since"] = json!(3);
        assert!(
            parse(&catalog_with(vec![since]))
                .unwrap_err()
                .contains("since 3")
        );

        let mut risky = entry("a");
        risky["privilege"] = json!("service_manager");
        risky["enabled_by_default"] = json!(true);
        assert!(
            parse(&catalog_with(vec![risky]))
                .unwrap_err()
                .contains("DEC-14")
        );

        let mut timeout = entry("a");
        timeout["timeout_seconds"] = json!(0);
        assert!(
            parse(&catalog_with(vec![timeout]))
                .unwrap_err()
                .contains("timeout_seconds 0")
        );

        let mut open = entry("a");
        open["parameters"]["additionalProperties"] = json!(true);
        assert!(
            parse(&catalog_with(vec![open]))
                .unwrap_err()
                .contains("not closed")
        );

        let mut extra = entry("a");
        extra["command"] = json!("/bin/true");
        assert!(
            parse(&catalog_with(vec![extra]))
                .unwrap_err()
                .contains("unknown field `command`")
        );

        let mut privilege = entry("a");
        privilege["privilege"] = json!("root");
        assert!(parse(&catalog_with(vec![privilege])).is_err());
    }

    #[test]
    fn type_ids_follow_the_catalog_pattern() {
        for good in ["a", "refresh_reports", "a1_b2", &"a".repeat(64)] {
            assert!(is_type_id(good), "{good}");
        }
        for bad in [
            "",
            "1a",
            "_a",
            "A",
            "a-b",
            "a.b",
            "a b",
            &"a".repeat(65),
            "EXAMPLEkey01.EXAMPLE-secret",
        ] {
            assert!(!is_type_id(bad), "{bad}");
        }
    }
}
