//! Checks the agent's view of the API contract in `docs/api` (P0-CONTRACT, NFR-5). The server's
//! contract spec checks the same files; see `docs/api/README.md`.

mod support;

use support::contract;

#[test]
fn every_schema_compiles_as_draft_2020_12() {
    let versions = contract::versions();
    assert!(versions.contains(&"v1".to_owned()), "found {versions:?}");
    for version in &versions {
        let names = contract::schema_names(version);
        assert!(!names.is_empty(), "no schemas in {version}");
        for name in names {
            // Panics with the schema's name if it is not a valid draft 2020-12 schema.
            contract::validator(version, &name);
        }
    }
}

#[test]
fn the_agent_schema_version_has_schemas() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_fleet-agent"))
        .arg("--version")
        .output()
        .expect("run fleet-agent");
    let stdout = String::from_utf8(output.stdout).expect("utf-8 output");
    let version = stdout
        .trim_end()
        .strip_suffix(')')
        .and_then(|s| s.rsplit_once("agent schema "))
        .map(|(_, n)| n)
        .unwrap_or_else(|| panic!("unexpected --version output: {stdout}"));
    let dir = format!("v{version}");
    assert!(
        contract::versions().contains(&dir),
        "fleet-agent reports schema {version} but docs/api/schemas/{dir} does not exist"
    );
}

#[test]
fn examples_validate_or_fail_as_named() {
    let examples = contract::examples();
    assert!(
        !examples.is_empty(),
        "no examples under {}",
        contract::root().display()
    );
    let mut wrong = Vec::new();
    for example in &examples {
        let errors = contract::errors(&example.version, &example.schema, &example.data());
        match (example.kind.as_str(), errors.is_empty()) {
            ("valid", false) => {
                wrong.push(format!("{} should validate: {errors:?}", example.label()))
            }
            ("invalid", true) => wrong.push(format!("{} should be rejected", example.label())),
            _ => {}
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn assert_conforms_reports_errors() {
    let heartbeat = serde_json::json!({
        "schema_version": 1,
        "agent_version": env!("CARGO_PKG_VERSION"),
        "hostname": "vm-01.example.lan",
        "uptime_seconds": 5,
        "agent_time": "2026-01-01T12:00:00Z"
    });
    contract::assert_conforms("v1", "heartbeat.request", &heartbeat);

    let result = std::panic::catch_unwind(|| {
        contract::assert_conforms(
            "v1",
            "heartbeat.request",
            &serde_json::json!({ "uptime_seconds": -1 }),
        );
    });
    assert!(result.is_err(), "an invalid heartbeat must not conform");
}

/// P3-A01, P3-S01: the catalog compiled into the agent is the shared file itself
/// (`include_str!` in `src/tasks/catalog.rs`), so the agent and the server cannot disagree on what a
/// task type is. The unit test beside the constant compares the compiled-in bytes with the file.
#[test]
fn the_agent_compiles_in_the_shared_task_catalog() {
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(crate_dir.join("src/tasks/catalog.rs"))
        .expect("read src/tasks/catalog.rs");
    let (_, rest) = source
        .split_once("include_str!(\"")
        .expect("src/tasks/catalog.rs compiles the catalog in with include_str!");
    let (path, _) = rest.split_once('"').unwrap();
    let included = crate_dir
        .join("src/tasks")
        .join(path)
        .canonicalize()
        .unwrap_or_else(|e| panic!("{path}: {e}"));
    let shared = contract::root()
        .join("tasks/task-catalog.json")
        .canonicalize()
        .unwrap();
    assert_eq!(included, shared);
    assert_eq!(
        source.matches("include_str!(").count(),
        1,
        "one catalog only"
    );
}

/// The shared catalog passes the structural half of the catalog lint (P3-S01) as the agent's
/// validator reads it, so both sides agree on the schema too.
#[test]
fn the_task_catalog_conforms_to_its_schema() {
    let root = contract::root().join("tasks");
    let read = |name: &str| -> serde_json::Value {
        let path = root.join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
    };
    let schema = read("task-catalog.schema.json");
    let validator = jsonschema::draft202012::new(&schema).expect("the catalog schema compiles");
    let catalog = read("task-catalog.json");
    let errors: Vec<String> = validator
        .iter_errors(&catalog)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
}
