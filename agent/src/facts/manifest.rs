//! The fact manifest as the agent reads it (`config-manifest.response`, P2-S01, P2-A01).
//!
//! The manifest is data from the server. It names fact keys and limits, never commands (the agent
//! decides how to read each key it knows), and this reader treats it as untrusted input all the same:
//!
//! - at most [`MAX_FACTS`] facts are kept (the contract's own bound on a report); the rest are counted;
//! - a key that does not look like a fact key is dropped and counted, because a report that contained
//!   it would be refused whole by the server's schema (`propertyNames`), and a repeated key keeps the
//!   first;
//! - a type this agent does not know is kept as [`FactType::Unknown`], so the fact is reported as
//!   `unsupported` rather than silently left out (AC-2.5);
//! - limits are read as whole numbers, defaulting as the server does ([`Limits::for_type`]) when absent
//!   or malformed, and are then clamped to this agent's own hard caps, so a hostile manifest cannot ask
//!   the agent to build a list of a million entries.
//!
//! Nothing here touches the host.

use serde_json::Value;

use crate::logging::sanitize;

/// The most facts one report holds (`facts.maxProperties` in `config.request`).
pub const MAX_FACTS: usize = 2000;
/// The largest manifest version a report may state (`manifest_version.maximum` in `config.request`).
pub const MAX_VERSION: u64 = 1_000_000;
/// The longest fact key (`propertyNames.maxLength` in `config.request`).
const MAX_KEY_CHARS: usize = 256;

/// Hard caps on the limits a manifest may ask for, whatever it says.
const HARD_MAX_STRING: u64 = 65_536;
const HARD_MAX_ITEMS: u64 = 10_000;
const SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactType {
    String,
    Integer,
    Boolean,
    StringList,
    FileAttributes,
    ServiceState,
    /// A type name this agent does not know.
    Unknown(String),
}

impl FactType {
    fn parse(name: &str) -> Self {
        match name {
            "string" => Self::String,
            "integer" => Self::Integer,
            "boolean" => Self::Boolean,
            "string_list" => Self::StringList,
            "file_attributes" => Self::FileAttributes,
            "service_state" => Self::ServiceState,
            other => Self::Unknown(sanitize(other, 32)),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::String => "string",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
            Self::StringList => "string_list",
            Self::FileAttributes => "file_attributes",
            Self::ServiceState => "service_state",
            Self::Unknown(name) => name,
        }
    }
}

/// The limits on a value, as the manifest states them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_length: usize,
    pub minimum: i64,
    pub maximum: i64,
    pub max_items: usize,
    pub item_max_length: usize,
}

impl Limits {
    /// The server's defaults (`ConfigManifest::CONSTRAINTS`) for a fact that states none.
    pub fn for_type(_: &FactType) -> Self {
        Self {
            max_length: 256,
            minimum: -SAFE_INTEGER,
            maximum: SAFE_INTEGER,
            max_items: 200,
            item_max_length: 256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFact {
    pub key: String,
    pub ty: FactType,
    pub limits: Limits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub version: u64,
    /// In the server's order (sorted by key).
    pub facts: Vec<ManifestFact>,
    /// What was dropped or defaulted, already safe to log, at most [`MAX_NOTES`] of them.
    pub notes: Vec<String>,
}

const MAX_NOTES: usize = 16;

/// Reads a `config-manifest.response` body. Fails only when there is no usable `manifest_version`;
/// everything else wrong with a fact is dropped or defaulted and noted.
pub fn parse(body: &Value) -> Result<Manifest, String> {
    let object = body.as_object().ok_or("the manifest is not an object")?;
    let version = object
        .get("manifest_version")
        .and_then(Value::as_u64)
        .filter(|v| (1..=MAX_VERSION).contains(v))
        .ok_or_else(|| {
            format!("`manifest_version` is missing or not a whole number from 1 to {MAX_VERSION}")
        })?;
    let listed = object
        .get("facts")
        .and_then(Value::as_array)
        .ok_or("`facts` is missing or not a list")?;

    let mut notes = Notes::default();
    let mut facts: Vec<ManifestFact> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut over_limit = 0usize;
    for entry in listed {
        let Some(entry) = entry.as_object() else {
            notes.push("a fact that is not an object was dropped");
            continue;
        };
        let Some(key) = entry.get("key").and_then(Value::as_str) else {
            notes.push("a fact without a key was dropped");
            continue;
        };
        if !valid_key(key) {
            notes.push(format!(
                "the fact key `{}` is not a valid key and was dropped",
                sanitize(key, 64)
            ));
            continue;
        }
        if !seen.insert(key.to_owned()) {
            notes.push(format!(
                "the fact `{key}` is listed twice; the first is used"
            ));
            continue;
        }
        if facts.len() >= MAX_FACTS {
            over_limit += 1;
            continue;
        }
        let ty = entry
            .get("type")
            .and_then(Value::as_str)
            .map_or_else(|| FactType::Unknown(String::new()), FactType::parse);
        let limits = limits(entry, &ty, key, &mut notes);
        facts.push(ManifestFact {
            key: key.to_owned(),
            ty,
            limits,
        });
    }
    if over_limit > 0 {
        notes.push(format!(
            "the manifest lists more than {MAX_FACTS} facts; {over_limit} were left out"
        ));
    }
    Ok(Manifest {
        version,
        facts,
        notes: notes.0,
    })
}

#[derive(Default)]
struct Notes(Vec<String>);

impl Notes {
    fn push(&mut self, note: impl Into<String>) {
        if self.0.len() < MAX_NOTES {
            self.0.push(note.into());
        }
    }
}

/// The shapes `config.request` allows as a fact key: `sshd.permitrootlogin`, `file:/etc/passwd`,
/// `service:ssh.service`. (The server's manifest holds the same patterns with shorter bounds.)
pub fn valid_key(key: &str) -> bool {
    if key.is_empty() || key.chars().count() > MAX_KEY_CHARS {
        return false;
    }
    if let Some(path) = key.strip_prefix("file:") {
        return path.starts_with('/')
            && (2..=201).contains(&path.len())
            && path.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'+' | b'-')
            });
    }
    if let Some(unit) = key.strip_prefix("service:") {
        return (1..=100).contains(&unit.len())
            && unit.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'+' | b'-')
            });
    }
    let mut parts = key.split('.');
    let first = parts.next().unwrap_or("");
    let rest: Vec<&str> = parts.collect();
    let word = |part: &str, start_with_letter: bool| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            && (!start_with_letter || part.as_bytes()[0].is_ascii_lowercase())
    };
    word(first, true) && !rest.is_empty() && rest.iter().all(|part| word(part, false))
}

fn limits(
    entry: &serde_json::Map<String, Value>,
    ty: &FactType,
    key: &str,
    notes: &mut Notes,
) -> Limits {
    let default = Limits::for_type(ty);
    let mut number = |name: &str| -> Option<i64> {
        match entry.get(name) {
            None | Some(Value::Null) => None,
            Some(value) => {
                // A range check, not `abs()`: `i64::MIN.abs()` overflows (review of #114).
                let parsed = value
                    .as_i64()
                    .filter(|n| (-SAFE_INTEGER..=SAFE_INTEGER).contains(n));
                if parsed.is_none() {
                    notes.push(format!(
                        "`{name}` of `{}` is not a whole number; the default is used",
                        sanitize(key, 64)
                    ));
                }
                parsed
            }
        }
    };
    let positive = |value: Option<i64>, default: usize, cap: u64| -> usize {
        value
            .filter(|n| *n >= 1)
            .map_or(default, |n| (n as u64).min(cap) as usize)
    };
    let max_length = positive(number("max_length"), default.max_length, HARD_MAX_STRING);
    let max_items = positive(number("max_items"), default.max_items, HARD_MAX_ITEMS);
    let item_max_length = positive(
        number("item_max_length"),
        default.item_max_length,
        HARD_MAX_STRING,
    );
    let minimum = number("minimum").unwrap_or(default.minimum);
    let maximum = number("maximum").unwrap_or(default.maximum);
    let (minimum, maximum) = if minimum <= maximum {
        (minimum, maximum)
    } else {
        notes.push(format!(
            "`minimum` of `{}` is above its `maximum`; the defaults are used",
            sanitize(key, 64)
        ));
        (default.minimum, default.maximum)
    };
    Limits {
        max_length,
        minimum,
        maximum,
        max_items,
        item_max_length,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse_ok(body: Value) -> Manifest {
        parse(&body).expect("a usable manifest")
    }

    #[test]
    fn reads_types_limits_and_defaults() {
        let manifest = parse_ok(json!({
            "schema_version": 1,
            "manifest_version": 3,
            "facts": [
                {"key": "sshd.maxauthtries", "type": "integer", "since": 1, "description": "x",
                 "minimum": 0, "maximum": 1000},
                {"key": "sshd.banner", "type": "string", "since": 1, "description": "x"},
                {"key": "services.running", "type": "string_list", "since": 1, "description": "x",
                 "max_items": 1000},
                {"key": "file:/etc/passwd", "type": "file_attributes", "since": 1, "description": "x"},
                {"key": "service:ssh.service", "type": "service_state", "since": 1, "description": "x"}
            ]
        }));
        assert_eq!(manifest.version, 3);
        assert!(manifest.notes.is_empty(), "{:?}", manifest.notes);
        let by_key = |key: &str| manifest.facts.iter().find(|f| f.key == key).unwrap();
        let tries = by_key("sshd.maxauthtries");
        assert_eq!(tries.ty, FactType::Integer);
        assert_eq!((tries.limits.minimum, tries.limits.maximum), (0, 1000));
        assert_eq!(by_key("sshd.banner").limits.max_length, 256);
        let list = by_key("services.running");
        assert_eq!(
            (list.limits.max_items, list.limits.item_max_length),
            (1000, 256)
        );
        assert_eq!(by_key("file:/etc/passwd").ty, FactType::FileAttributes);
        assert_eq!(by_key("service:ssh.service").ty, FactType::ServiceState);
    }

    #[test]
    fn a_manifest_without_a_usable_version_is_refused() {
        for body in [
            json!(null),
            json!([]),
            json!({"facts": []}),
            json!({"manifest_version": 0, "facts": []}),
            json!({"manifest_version": -1, "facts": []}),
            json!({"manifest_version": "1", "facts": []}),
            json!({"manifest_version": 1_000_001, "facts": []}),
            json!({"manifest_version": 1}),
            json!({"manifest_version": 1, "facts": {}}),
        ] {
            assert!(parse(&body).is_err(), "{body}");
        }
        assert!(parse(&json!({"manifest_version": 1, "facts": []})).is_ok());
    }

    #[test]
    fn unknown_types_are_kept_so_they_are_reported_unsupported() {
        let manifest = parse_ok(json!({"manifest_version": 1, "facts": [
            {"key": "sshd.future", "type": "ip_address"},
            {"key": "sshd.typeless"}
        ]}));
        assert_eq!(manifest.facts.len(), 2);
        assert_eq!(manifest.facts[0].ty, FactType::Unknown("ip_address".into()));
        assert_eq!(manifest.facts[1].ty, FactType::Unknown(String::new()));
    }

    #[test]
    fn keys_the_report_schema_would_refuse_are_dropped_and_noted() {
        let long = format!("file:/{}", "a".repeat(250));
        let facts: Vec<Value> = [
            "Sshd.Upper",
            "nodot",
            "sshd.",
            ".sshd",
            "1sshd.x",
            "file:relative/path",
            "file:/has space",
            "service:",
            "service:bad/slash",
            long.as_str(),
            "sshd.ok_key1",
            "file:/etc/ok-file+1",
            "service:getty@tty1.service",
        ]
        .iter()
        .map(|key| json!({"key": key, "type": "string"}))
        .collect();
        let manifest = parse_ok(json!({"manifest_version": 1, "facts": facts}));
        let kept: Vec<_> = manifest.facts.iter().map(|f| f.key.as_str()).collect();
        assert_eq!(
            kept,
            [
                "sshd.ok_key1",
                "file:/etc/ok-file+1",
                "service:getty@tty1.service"
            ]
        );
        assert_eq!(manifest.notes.len(), 10);
    }

    #[test]
    fn a_repeated_key_keeps_the_first() {
        let manifest = parse_ok(json!({"manifest_version": 1, "facts": [
            {"key": "sshd.a", "type": "string", "max_length": 5},
            {"key": "sshd.a", "type": "integer"}
        ]}));
        assert_eq!(manifest.facts.len(), 1);
        assert_eq!(manifest.facts[0].ty, FactType::String);
        assert_eq!(manifest.notes.len(), 1);
    }

    #[test]
    fn a_huge_manifest_is_bounded() {
        let facts: Vec<Value> = (0..MAX_FACTS + 500)
            .map(|i| json!({"key": format!("sshd.k{i}"), "type": "string"}))
            .collect();
        let manifest = parse_ok(json!({"manifest_version": 1, "facts": facts}));
        assert_eq!(manifest.facts.len(), MAX_FACTS);
        assert!(
            manifest
                .notes
                .iter()
                .any(|n| n.contains("500 were left out"))
        );
    }

    #[test]
    fn hostile_limits_are_defaulted_or_clamped() {
        let manifest = parse_ok(json!({"manifest_version": 1, "facts": [
            {"key": "a.list", "type": "string_list", "max_items": 100000000, "item_max_length": 99999999},
            {"key": "a.string", "type": "string", "max_length": "lots"},
            {"key": "a.zero", "type": "string", "max_length": 0},
            {"key": "a.int", "type": "integer", "minimum": 10, "maximum": 5},
            {"key": "a.float", "type": "integer", "minimum": 1.5},
            {"key": "a.big", "type": "integer", "maximum": 9007199254740993_u64}
        ]}));
        let by_key = |key: &str| manifest.facts.iter().find(|f| f.key == key).unwrap().limits;
        assert_eq!(by_key("a.list").max_items, 10_000);
        assert_eq!(by_key("a.list").item_max_length, 65_536);
        assert_eq!(by_key("a.string").max_length, 256);
        assert_eq!(by_key("a.zero").max_length, 256);
        assert_eq!(by_key("a.int").minimum, -SAFE_INTEGER);
        assert_eq!(by_key("a.int").maximum, SAFE_INTEGER);
        assert_eq!(by_key("a.float").minimum, -SAFE_INTEGER);
        assert_eq!(by_key("a.big").maximum, SAFE_INTEGER);
        assert!(!manifest.notes.is_empty());
    }

    #[test]
    fn the_most_negative_integer_as_a_limit_is_defaulted_not_a_panic() {
        // Review of #114: `abs()` of i64::MIN overflowed (a panic with overflow checks, a negative
        // number that passed the cap without them).
        let manifest = parse_ok(json!({"manifest_version": 1, "facts": [
            {"key": "a.min", "type": "integer", "minimum": i64::MIN, "maximum": i64::MIN},
            {"key": "a.len", "type": "string", "max_length": i64::MIN}
        ]}));
        let by_key = |key: &str| manifest.facts.iter().find(|f| f.key == key).unwrap().limits;
        assert_eq!(by_key("a.min").minimum, -SAFE_INTEGER);
        assert_eq!(by_key("a.min").maximum, SAFE_INTEGER);
        assert_eq!(by_key("a.len").max_length, 256);
        assert!(
            manifest
                .notes
                .iter()
                .any(|n| n.contains("`minimum` of `a.min`"))
        );
    }

    #[test]
    fn notes_are_bounded_and_safe_to_log() {
        let facts: Vec<Value> = (0..100)
            .map(|i| json!({"key": format!("Bad\nKey{i}"), "type": "string"}))
            .collect();
        let manifest = parse_ok(json!({"manifest_version": 1, "facts": facts}));
        assert!(manifest.facts.is_empty());
        assert_eq!(manifest.notes.len(), MAX_NOTES);
        assert!(manifest.notes.iter().all(|n| !n.contains('\n')));
    }

    #[test]
    fn the_published_example_manifest_parses_without_notes() {
        let path = crate::collect::contract::root()
            .join("examples/v1/config-manifest.response/valid/all-types.json");
        let body: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let manifest = parse_ok(body);
        assert!(manifest.notes.is_empty(), "{:?}", manifest.notes);
        assert!(manifest.facts.len() >= 6);
        assert!(
            manifest
                .facts
                .iter()
                .all(|f| !matches!(f.ty, FactType::Unknown(_)))
        );
    }
}
