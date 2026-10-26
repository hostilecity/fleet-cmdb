//! Reads the agent API contract from `docs/api` (P0-CONTRACT, NFR-5). Schemas and examples live only
//! there; agent tests must load them through this module rather than keeping copies.
//!
//! Report structs are checked with
//! `assert_conforms("v1", "inventory.request", &serde_json::to_value(&report)?)`.

#![allow(dead_code)] // Not every test binary uses every helper.

use std::fs;
use std::path::{Path, PathBuf};

use jsonschema::Validator;
use serde_json::Value;

/// `docs/api`, found relative to this crate so tests work from any directory.
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/api")
}

fn read_json(path: &Path) -> Value {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn sorted_children(dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect();
    paths.sort();
    paths
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .expect("file name")
        .to_string_lossy()
        .into_owned()
}

/// Schema versions present, for example `["v1"]`.
pub fn versions() -> Vec<String> {
    sorted_children(&root().join("schemas"))
        .iter()
        .filter(|p| p.is_dir())
        .map(|p| file_name(p))
        .collect()
}

/// Schema names in a version, for example `heartbeat.request`.
pub fn schema_names(version: &str) -> Vec<String> {
    sorted_children(&root().join("schemas").join(version))
        .iter()
        .filter_map(|p| file_name(p).strip_suffix(".schema.json").map(str::to_owned))
        .collect()
}

/// The schema `docs/api/schemas/<version>/<name>.schema.json`.
pub fn schema(version: &str, name: &str) -> Value {
    read_json(&root().join(format!("schemas/{version}/{name}.schema.json")))
}

/// A draft 2020-12 validator for the named schema.
pub fn validator(version: &str, name: &str) -> Validator {
    jsonschema::draft202012::new(&schema(version, name))
        .unwrap_or_else(|e| panic!("schemas/{version}/{name}: invalid schema: {e}"))
}

/// Validation error messages; empty when the value conforms.
pub fn errors(version: &str, name: &str, value: &Value) -> Vec<String> {
    validator(version, name)
        .iter_errors(value)
        .map(|e| format!("{} at {}", e, e.instance_path()))
        .collect()
}

/// Panics with every validation error unless `value` conforms to the schema.
pub fn assert_conforms(version: &str, name: &str, value: &Value) {
    let errors = errors(version, name, value);
    assert!(
        errors.is_empty(),
        "payload does not conform to schemas/{version}/{name}:\n  {}",
        errors.join("\n  ")
    );
}

/// One example payload from `docs/api/examples`.
pub struct Example {
    pub version: String,
    pub schema: String,
    /// `valid` or `invalid`.
    pub kind: String,
    pub path: PathBuf,
}

impl Example {
    pub fn data(&self) -> Value {
        read_json(&self.path)
    }

    pub fn label(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.version,
            self.schema,
            self.kind,
            file_name(&self.path)
        )
    }
}

/// Every example, in a stable order.
pub fn examples() -> Vec<Example> {
    let mut out = Vec::new();
    for version_dir in sorted_children(&root().join("examples")) {
        for schema_dir in sorted_children(&version_dir) {
            for kind in ["valid", "invalid"] {
                let kind_dir = schema_dir.join(kind);
                if !kind_dir.is_dir() {
                    continue;
                }
                for path in sorted_children(&kind_dir) {
                    if path.extension().is_some_and(|e| e == "json") {
                        out.push(Example {
                            version: file_name(&version_dir),
                            schema: file_name(&schema_dir),
                            kind: kind.to_owned(),
                            path,
                        });
                    }
                }
            }
        }
    }
    out
}
