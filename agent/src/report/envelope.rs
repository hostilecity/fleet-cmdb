//! The heartbeat response envelope, `{"server_time", "directives"}` (FR-1.2, DEC-08, DEC-20).
//!
//! Parsing never fails: anything this agent does not understand is ignored and listed, so the caller
//! can log it, and the heartbeat still counts as accepted. The agent protocol outlives server releases
//! (ADR 0019), so an older agent must keep working whatever a newer server adds.
//!
//! `directives` is an object keyed by directive name ([ADR 0020]). Every directive is optional, an
//! absent or `null` directive or field means no instruction, and unknown names are ignored:
//!
//! - `intervals`: `{"heartbeat_seconds": n, "inventory_seconds": n}`, either optional, whole seconds.
//!   The caller clamps each value to the config bounds ([`crate::config::Interval`], ADR 0019).
//! - `agent_update`: `rollout_id`, `version`, and the manifest, signature, and binary URLs, all required.
//!   Kept as raw JSON for the updater (P1-AGENT-UPDATE) once its fields are well formed; a directive that
//!   lacks one, or has one of the wrong kind, is a problem and is not kept. Not acted on in this build.
//! - `report_request`: `{"types": ["config", ...]}`, at least one type and each once (DEC-13, P2-S03).
//!   The types this agent sends on request ([`ReportType`]) are kept; a type it does not know is
//!   ignored and listed, so a type added later is additive. A directive that is not an object, or
//!   whose `types` is missing, empty, not a list of strings, or repeats a type, is a problem and
//!   asks for nothing.
//! - any other name is ignored and listed.
//!
//! A missing or `null` `directives` is read as `{}`. Any other shape, including the array that ADR 0008
//! first planned, is a problem: listed, ignored, and never fatal.
//!
//! [ADR 0020]: ../../../docs/decisions/0020-named-heartbeat-directives.md

use serde_json::Value;

use super::requests::ReportType;
use crate::logging::sanitize;

/// How many ignored names one response may list; the rest are counted.
const MAX_LISTED: usize = 16;
/// Longest name quoted from the server in a log line.
const MAX_NAME_CHARS: usize = 64;

/// Intervals the server asked for, in seconds, before clamping. `None` means the server did not ask.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ServerIntervals {
    pub heartbeat_seconds: Option<u64>,
    pub inventory_seconds: Option<u64>,
}

/// What a heartbeat response said, as far as this agent understands it.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Envelope {
    /// `server_time`, if it was a string.
    pub server_time: Option<String>,
    pub intervals: ServerIntervals,
    /// The `agent_update` directive, untouched, for P1-AGENT-UPDATE.
    pub agent_update: Option<Value>,
    /// The report types the `report_request` directive asked for that this agent sends on request.
    pub report_types: Vec<ReportType>,
    /// The `report_request` directive was there but could not be read (or the response or its
    /// `directives` was not an object, so whether it was there is unknown). The request state is then
    /// left as it is, rather than ending the episode as an absent directive does (Rust practice review
    /// of #114).
    pub report_request_unreadable: bool,
    /// Fields and directives present but not understood by this agent, already safe to log.
    pub ignored: Vec<String>,
    /// Values present in a known place but malformed, already safe to log. Each is ignored.
    pub problems: Vec<String>,
}

impl Envelope {
    fn ignore(&mut self, name: String) {
        self.ignored.push(name);
    }
}

/// Reads a heartbeat response body.
pub fn parse(body: &Value) -> Envelope {
    let mut envelope = Envelope::default();
    let Some(object) = body.as_object() else {
        envelope
            .problems
            .push(format!("the response is {}, not an object", kind(body)));
        envelope.report_request_unreadable = true;
        return envelope;
    };
    let mut unknown = Names::default();
    for (key, value) in object {
        match key.as_str() {
            "server_time" => match value.as_str() {
                Some(text) => envelope.server_time = Some(sanitize(text, MAX_NAME_CHARS)),
                None => envelope
                    .problems
                    .push(format!("`server_time` is {}, not a string", kind(value))),
            },
            "directives" => directives(value, &mut envelope),
            other => unknown.push(format!("field `{}`", name(other))),
        }
    }
    unknown.finish(&mut envelope);
    envelope
}

fn directives(value: &Value, envelope: &mut Envelope) {
    let mut unknown = Names::default();
    match value {
        Value::Null => {}
        Value::Object(map) => {
            for (key, value) in map {
                match key.as_str() {
                    "intervals" => intervals(value, envelope),
                    "agent_update" => match value {
                        Value::Object(fields) => match agent_update_problem(fields) {
                            None => envelope.agent_update = Some(value.clone()),
                            Some(problem) => envelope.problems.push(problem),
                        },
                        Value::Null => {}
                        other => envelope.problems.push(format!(
                            "directive `agent_update` is {}, not an object",
                            kind(other)
                        )),
                    },
                    "report_request" => report_request(value, envelope),
                    other => unknown.push(format!("directive `{}`", name(other))),
                }
            }
        }
        // Includes an array, the shape ADR 0008 first planned (amended by ADR 0020).
        other => {
            envelope
                .problems
                .push(format!("`directives` is {}, not an object", kind(other)));
            envelope.report_request_unreadable = true;
        }
    }
    unknown.finish(envelope);
}

/// Most entries of `report_request.types` that are looked at: there are only a few report types.
const MAX_REPORT_TYPES: usize = 64;

fn report_request(value: &Value, envelope: &mut Envelope) {
    let fields = match value {
        Value::Object(fields) => fields,
        Value::Null => return,
        other => {
            envelope.problems.push(format!(
                "directive `report_request` is {}, not an object",
                kind(other)
            ));
            envelope.report_request_unreadable = true;
            return;
        }
    };
    let mut unknown = Names::default();
    let mut types = None;
    for (key, value) in fields {
        match key.as_str() {
            "types" => types = Some(value),
            other => unknown.push(format!("directive `report_request.{}`", name(other))),
        }
    }
    unknown.finish(envelope);
    let problem = |what: &str| format!("directive `report_request.types` {what}");
    let Some(Value::Array(list)) = types else {
        envelope.problems.push(problem("is missing or not a list"));
        envelope.report_request_unreadable = true;
        return;
    };
    if list.is_empty() || list.len() > MAX_REPORT_TYPES {
        envelope
            .problems
            .push(problem("is empty or has far too many entries"));
        envelope.report_request_unreadable = true;
        return;
    }
    let mut seen: Vec<&str> = Vec::new();
    let mut known = Vec::new();
    let mut unknown_types = Names::default();
    for item in list {
        let Some(text) = item.as_str() else {
            envelope
                .problems
                .push(problem("has an entry that is not a string"));
            envelope.report_request_unreadable = true;
            return;
        };
        if seen.contains(&text) {
            envelope
                .problems
                .push(problem("names a type more than once"));
            envelope.report_request_unreadable = true;
            return;
        }
        seen.push(text);
        match ReportType::from_name(text) {
            Some(ty) => known.push(ty),
            None => unknown_types.push(format!("report type `{}`", name(text))),
        }
    }
    envelope.report_types = known;
    unknown_types.finish(envelope);
}

/// The first thing wrong with an `agent_update` directive's fields, or `None`. The text names fields
/// only, never the server's values. The agent still verifies the release itself (ADR 0018); this only
/// keeps a directive it could not follow from reaching the updater.
fn agent_update_problem(fields: &serde_json::Map<String, Value>) -> Option<String> {
    let problem = |field: &str, want: &str| {
        Some(format!(
            "directive `agent_update.{field}` is missing or not {want}"
        ))
    };
    if fields
        .get("rollout_id")
        .and_then(Value::as_u64)
        .is_none_or(|id| id == 0)
    {
        return problem("rollout_id", "a positive whole number");
    }
    let version = fields.get("version").and_then(Value::as_str);
    if !version.is_some_and(|v| semver::Version::parse(v).is_ok_and(|v| v.build.is_empty())) {
        return problem("version", "a semantic version without build metadata");
    }
    for field in ["manifest_url", "signature_url", "binary_url"] {
        let url = fields.get(field).and_then(Value::as_str);
        if !url.is_some_and(|u| u.starts_with("https://") && !u.contains(char::is_whitespace)) {
            return problem(field, "an https URL");
        }
    }
    None
}

fn intervals(value: &Value, envelope: &mut Envelope) {
    let map = match value {
        Value::Object(map) => map,
        Value::Null => return,
        other => {
            envelope.problems.push(format!(
                "directive `intervals` is {}, not an object",
                kind(other)
            ));
            return;
        }
    };
    let mut unknown = Names::default();
    for (key, value) in map {
        let slot = match key.as_str() {
            "heartbeat_seconds" => &mut envelope.intervals.heartbeat_seconds,
            "inventory_seconds" => &mut envelope.intervals.inventory_seconds,
            other => {
                unknown.push(format!("directive `intervals.{}`", name(other)));
                continue;
            }
        };
        match value {
            Value::Null => {}
            // `as_u64` is `None` for negative numbers and fractions, so only whole seconds pass.
            v => match v.as_u64() {
                Some(seconds) => *slot = Some(seconds),
                None => envelope.problems.push(format!(
                    "directive `intervals.{key}` is {}, not a whole number of seconds",
                    describe(v)
                )),
            },
        }
    }
    unknown.finish(envelope);
}

/// Collects ignored names, keeping at most [`MAX_LISTED`] per list.
#[derive(Default)]
struct Names {
    listed: Vec<String>,
    more: usize,
}

impl Names {
    fn push(&mut self, name: String) {
        if self.listed.len() < MAX_LISTED {
            self.listed.push(name);
        } else {
            self.more += 1;
        }
    }

    fn finish(self, envelope: &mut Envelope) {
        for name in self.listed {
            envelope.ignore(name);
        }
        if self.more > 0 {
            envelope.ignore(format!("{} more", self.more));
        }
    }
}

/// A name from the server, made safe for one log line.
fn name(text: &str) -> String {
    sanitize(text, MAX_NAME_CHARS)
}

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "a list",
        Value::Object(_) => "an object",
    }
}

/// A short description of a bad value: numbers are quoted (they are short), anything else by kind.
fn describe(value: &Value) -> String {
    match value {
        Value::Number(n) => sanitize(&n.to_string(), 32),
        other => kind(other).to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn no_directives_means_nothing_to_act_on() {
        for directives in [
            json!({}),
            json!(null),
            json!({"intervals": null, "agent_update": null}),
        ] {
            let envelope =
                parse(&json!({"server_time": "2026-01-01T12:00:00Z", "directives": directives}));
            assert_eq!(
                envelope,
                Envelope {
                    server_time: Some("2026-01-01T12:00:00Z".into()),
                    ..Envelope::default()
                },
                "{directives}"
            );
        }
        // A missing `directives` is read as `{}` too.
        let envelope = parse(&json!({"server_time": "2026-01-01T12:00:00Z"}));
        assert!(envelope.problems.is_empty() && envelope.ignored.is_empty());
    }

    #[test]
    fn an_array_of_directives_is_a_problem_and_nothing_in_it_is_read() {
        for directives in [
            json!([]),
            json!([{"type": "intervals", "heartbeat_seconds": 30}]),
            json!([{"intervals": {"heartbeat_seconds": 30}}, {"agent_update": {"version": "9.9.9"}}]),
        ] {
            let envelope = parse(&json!({"directives": directives}));
            assert_eq!(
                envelope.problems,
                ["`directives` is a list, not an object"],
                "{directives}"
            );
            assert_eq!(
                envelope.intervals,
                ServerIntervals::default(),
                "{directives}"
            );
            assert_eq!(envelope.agent_update, None, "{directives}");
            assert!(envelope.ignored.is_empty(), "{directives}");
        }
    }

    /// Every `heartbeat.response` example in `docs/api`, by kind (`valid` or `invalid`) and file name.
    fn contract_examples(kind: &str) -> Vec<(String, Value)> {
        let dir = crate::collect::contract::root()
            .join("examples/v1/heartbeat.response")
            .join(kind);
        let mut examples: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                (
                    name,
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap(),
                )
            })
            .collect();
        examples.sort_by(|a, b| a.0.cmp(&b.0));
        assert!(!examples.is_empty(), "no examples in {}", dir.display());
        examples
    }

    #[test]
    fn valid_contract_examples_parse_without_problems() {
        for (name, body) in contract_examples("valid") {
            let envelope = parse(&body);
            assert!(
                envelope.problems.is_empty(),
                "{name}: {:?}",
                envelope.problems
            );
            assert!(envelope.server_time.is_some(), "{name}");
            if name.starts_with("report-request") {
                // Only a report type this build does not send would be ignored.
                assert!(
                    envelope
                        .ignored
                        .iter()
                        .all(|i| i.starts_with("report type `")),
                    "{name}: {:?}",
                    envelope.ignored
                );
                continue;
            }
            if name.starts_with("tasks-available") {
                // The task poller (P3-A02, #34) reads `tasks_available`; until it does, this build
                // ignores the directive and logs it, as DEC-20 allows, and nothing else.
                assert!(
                    envelope
                        .ignored
                        .iter()
                        .all(|i| i.contains("`tasks_available`")),
                    "{name}: {:?}",
                    envelope.ignored
                );
                continue;
            }
            // Only `unknown-field-*` examples carry names this agent does not know.
            assert_eq!(
                envelope.ignored.is_empty(),
                !name.starts_with("unknown-field-"),
                "{name}: {:?}",
                envelope.ignored
            );
        }
        let intervals = contract_examples("valid")
            .into_iter()
            .find(|(name, _)| name == "intervals.json")
            .unwrap()
            .1;
        assert_eq!(
            parse(&intervals).intervals,
            ServerIntervals {
                heartbeat_seconds: Some(120),
                inventory_seconds: Some(1800)
            }
        );
    }

    #[test]
    fn invalid_contract_examples_are_noticed_and_not_acted_on() {
        for (name, body) in contract_examples("invalid") {
            let envelope = parse(&body);
            assert_eq!(envelope.agent_update, None, "{name}");
            assert!(envelope.report_types.is_empty(), "{name}: acted on");
            // A zero interval is the one value the agent reads as a number; the caller clamps it to
            // the configured minimum, so it cannot stop heartbeats.
            if name != "intervals-zero.json" {
                assert_eq!(envelope.intervals, ServerIntervals::default(), "{name}");
            }
            // `directives-missing.json` is read as `{}`: the agent has nothing to act on, which is
            // what an absent `directives` means.
            if name != "directives-missing.json" && name != "intervals-zero.json" {
                assert!(
                    !envelope.problems.is_empty() || !envelope.ignored.is_empty(),
                    "{name} parsed as if valid"
                );
            }
        }
    }

    /// A well formed `agent_update` directive, as `docs/api/examples/v1/heartbeat.response` shows.
    fn update() -> Value {
        json!({
            "rollout_id": 1,
            "version": "0.2.0",
            "manifest_url": "https://agent.example.lan/api/v1/releases/0.2.0/manifest",
            "signature_url": "https://agent.example.lan/api/v1/releases/0.2.0/signature",
            "binary_url": "https://agent.example.lan/api/v1/releases/0.2.0/binary"
        })
    }

    #[test]
    fn a_malformed_agent_update_is_a_problem_and_not_kept() {
        for (field, value) in [
            ("rollout_id", json!(0)),
            ("rollout_id", json!("1")),
            ("version", json!("latest")),
            ("version", json!("0.2.0+build.5")),
            ("version", json!(2)),
            ("manifest_url", json!("http://agent.example.lan/m")),
            ("signature_url", json!("https://agent.example.lan/a b")),
            ("binary_url", json!(null)),
        ] {
            let mut directive = update();
            directive[field] = value.clone();
            let envelope = parse(&json!({"directives": {"agent_update": directive}}));
            assert_eq!(envelope.agent_update, None, "{field} {value}");
            assert_eq!(
                envelope.problems.len(),
                1,
                "{field} {value}: {:?}",
                envelope.problems
            );
            assert!(
                envelope.problems[0].contains(field),
                "{:?}",
                envelope.problems
            );
        }
        for field in [
            "rollout_id",
            "version",
            "manifest_url",
            "signature_url",
            "binary_url",
        ] {
            let mut directive = update();
            directive.as_object_mut().unwrap().remove(field);
            let envelope = parse(&json!({"directives": {"agent_update": directive}}));
            assert_eq!(envelope.agent_update, None, "without {field}");
            assert!(
                envelope.problems[0].contains(field),
                "{:?}",
                envelope.problems
            );
        }
    }

    #[test]
    fn intervals_and_agent_update_are_read_from_an_object() {
        let envelope = parse(&json!({
            "server_time": "2026-01-01T12:00:00Z",
            "directives": {
                "intervals": {"heartbeat_seconds": 120, "inventory_seconds": 1800},
                "agent_update": update()
            }
        }));
        assert_eq!(
            envelope.intervals,
            ServerIntervals {
                heartbeat_seconds: Some(120),
                inventory_seconds: Some(1800)
            }
        );
        assert_eq!(envelope.agent_update, Some(update()));
        assert!(envelope.ignored.is_empty() && envelope.problems.is_empty());
    }

    #[test]
    fn a_malformed_report_request_asks_for_nothing() {
        for (directive, needle) in [
            (json!("config"), "is a string, not an object"),
            (json!([]), "is a list, not an object"),
            (json!({}), "is missing or not a list"),
            (json!({"types": "config"}), "is missing or not a list"),
            (json!({"types": []}), "is empty"),
            (json!({"types": ["config", 7]}), "not a string"),
            (
                json!({"types": ["config", "inventory", "config"]}),
                "more than once",
            ),
        ] {
            let envelope = parse(&json!({"directives": {"report_request": directive}}));
            assert!(envelope.report_types.is_empty(), "{directive}");
            assert!(envelope.report_request_unreadable, "{directive}");
            assert!(
                envelope.problems.iter().any(|p| p.contains(needle)),
                "{directive}: {:?}",
                envelope.problems
            );
        }
        let envelope = parse(&json!({"directives": {"report_request": null}}));
        assert!(envelope.report_types.is_empty() && envelope.problems.is_empty());
        assert!(!envelope.report_request_unreadable, "null is absent");
        assert!(!parse(&json!({"directives": {}})).report_request_unreadable);
        assert!(parse(&json!({"directives": []})).report_request_unreadable);
        assert!(parse(&json!([])).report_request_unreadable);
    }

    #[test]
    fn unknown_types_and_fields_of_a_report_request_are_listed_and_the_known_types_kept() {
        let envelope = parse(&json!({"directives": {"report_request": {
            "types": ["inventory", "firmware\nforged line", "packages"],
            "priority": "high"
        }}}));
        assert_eq!(
            envelope.report_types,
            [ReportType::Inventory, ReportType::Packages]
        );
        assert_eq!(
            envelope.ignored,
            [
                "directive `report_request.priority`",
                "report type `firmware forged line`",
            ]
        );
        assert!(envelope.problems.is_empty());
    }

    #[test]
    fn a_report_request_names_the_types_to_report_and_the_rest_is_still_read() {
        // P2-S03: `config`, `inventory`, and (P2-AGENT-PACKAGES) `packages` are reports this agent
        // sends on request.
        let (_, body) = contract_examples("valid")
            .into_iter()
            .find(|(name, _)| name == "report-request.json")
            .unwrap();
        assert!(body["directives"]["report_request"]["types"].is_array());
        let envelope = parse(&body);
        assert_eq!(
            envelope.report_types,
            [
                ReportType::Config,
                ReportType::Inventory,
                ReportType::Packages
            ]
        );
        assert!(envelope.ignored.is_empty(), "{:?}", envelope.ignored);
        assert!(envelope.problems.is_empty(), "{:?}", envelope.problems);
        assert_eq!(
            envelope.intervals,
            ServerIntervals {
                heartbeat_seconds: Some(120),
                inventory_seconds: Some(1800)
            }
        );
        assert_eq!(envelope.agent_update, None);
    }

    #[test]
    fn either_interval_may_be_absent_or_null() {
        let envelope = parse(&json!({"directives": {"intervals": {"heartbeat_seconds": 90}}}));
        assert_eq!(envelope.intervals.heartbeat_seconds, Some(90));
        assert_eq!(envelope.intervals.inventory_seconds, None);
        let envelope = parse(&json!({"directives": {"intervals": {"inventory_seconds": null}}}));
        assert_eq!(envelope.intervals, ServerIntervals::default());
        assert!(envelope.problems.is_empty());
    }

    #[test]
    fn unknown_directives_and_fields_are_listed_not_acted_on() {
        let envelope = parse(&json!({
            "server_time": "2026-01-01T12:00:00Z",
            "directives": {"collect_config": {}, "intervals": {"heartbeat_seconds": 60, "jitter": 3}},
            "motd": "hello"
        }));
        assert_eq!(envelope.intervals.heartbeat_seconds, Some(60));
        assert_eq!(
            envelope.ignored,
            [
                "directive `intervals.jitter`",
                "directive `collect_config`",
                "field `motd`"
            ]
        );
        assert!(envelope.problems.is_empty());
        // An unknown directive is ignored whatever its value, so a newer server can never break this agent.
        let envelope = parse(&json!({"directives": {"future": true, "later": [1], "soon": null}}));
        assert_eq!(
            envelope.ignored,
            [
                "directive `future`",
                "directive `later`",
                "directive `soon`"
            ]
        );
        assert!(envelope.problems.is_empty());
    }

    #[test]
    fn malformed_values_are_ignored_and_reported() {
        for (body, problem) in [
            (json!([]), "the response is a list, not an object"),
            (json!(null), "the response is null, not an object"),
            (json!({"server_time": 5}), "`server_time` is a number"),
            (
                json!({"directives": "all"}),
                "`directives` is a string, not an object",
            ),
            (
                json!({"directives": {"intervals": [60]}}),
                "directive `intervals` is a list",
            ),
            (
                json!({"directives": {"intervals": {"heartbeat_seconds": -5}}}),
                "`intervals.heartbeat_seconds` is -5, not a whole number",
            ),
            (
                json!({"directives": {"intervals": {"heartbeat_seconds": 1.5}}}),
                "is 1.5, not a whole number",
            ),
            (
                json!({"directives": {"intervals": {"inventory_seconds": "900"}}}),
                "`intervals.inventory_seconds` is a string",
            ),
            (
                json!({"directives": {"agent_update": "0.2.0"}}),
                "directive `agent_update` is a string",
            ),
        ] {
            let envelope = parse(&body);
            assert_eq!(envelope.intervals, ServerIntervals::default(), "{body}");
            assert_eq!(envelope.agent_update, None, "{body}");
            assert!(
                envelope.problems.iter().any(|p| p.contains(problem)),
                "{body}: {:?}",
                envelope.problems
            );
        }
    }

    #[test]
    fn a_huge_value_is_not_a_valid_interval() {
        // Larger than u64: serde_json keeps it as a float, which is refused rather than wrapped.
        let body: Value = serde_json::from_str(
            r#"{"directives":{"intervals":{"heartbeat_seconds":100000000000000000000}}}"#,
        )
        .unwrap();
        let envelope = parse(&body);
        assert_eq!(envelope.intervals.heartbeat_seconds, None);
        assert_eq!(envelope.problems.len(), 1, "{:?}", envelope.problems);
        // u64::MAX itself is a whole number; the caller clamps it to the config bound.
        let envelope =
            parse(&json!({"directives": {"intervals": {"heartbeat_seconds": u64::MAX}}}));
        assert_eq!(envelope.intervals.heartbeat_seconds, Some(u64::MAX));
    }

    #[test]
    fn names_from_the_server_are_sanitised_and_bounded() {
        let mut directives = serde_json::Map::new();
        directives.insert("evil\nINFO forged line".into(), json!({}));
        for i in 0..40 {
            directives.insert(format!("d{i:02}"), json!({}));
        }
        directives.insert("x".repeat(500), json!({}));
        let envelope = parse(&json!({ "directives": directives }));
        assert_eq!(envelope.ignored.len(), MAX_LISTED + 1);
        assert_eq!(envelope.ignored.last().unwrap(), "26 more");
        assert!(envelope.ignored.iter().all(|n| !n.contains('\n')));
        assert!(envelope.ignored.iter().all(|n| n.chars().count() < 100));
    }
}
