//! The task API as the agent speaks it (P3-S03, P3-S04, `docs/api/README.md` "Tasks"):
//! `POST /api/v1/tasks/poll` (`task-poll.*`), `POST /api/v1/tasks/<id>/start` (`task-start.*`), and
//! `POST /api/v1/tasks/<id>/result` (`task-result.*`). The tests check every request this module builds
//! against the schemas and read every example response.
//!
//! The poller sees only [`TaskApi`]. A response this agent cannot read is never a task: a poll reply
//! whose task is malformed, or a start reply without a readable `run`, is a failed request, so nothing
//! malformed is recorded or run. Progress (`task-progress.*`) is optional and left to the executor
//! (P3-A03).

use serde_json::{Map, Value, json};

use super::executor::Delivered;
use super::ledger::Outcome;
use crate::client::{ApiError, ApiResponse};
use crate::report::Transport;
use crate::{AGENT_SCHEMA_VERSION, AGENT_VERSION};

pub const POLL_PATH: &str = "/api/v1/tasks/poll";

pub fn start_path(id: &str) -> String {
    format!("/api/v1/tasks/{id}/start")
}

pub fn result_path(id: &str) -> String {
    format!("/api/v1/tasks/{id}/result")
}

/// What a poll returned: the task, or none.
pub type PollReply = Option<Delivered>;

/// What `start` or `result` returned, when the request itself got an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// `start`: `run: true`. `result`: stored (also a duplicate, or a late annotation).
    Accepted,
    /// `start`: `run: false`, with the server's state. `result`: refused for good (`409 task_conflict`,
    /// `404 not_found`, `422`), with the error code. Sending it again cannot help.
    Rejected(String),
}

/// The task endpoints. [`Api`] over the agent's [`Transport`] in production; a fake in tests.
pub trait TaskApi {
    fn poll(&self) -> Result<PollReply, ApiError>;
    /// `started_at` is the `started` record's time (RFC 3339 UTC).
    fn start(&self, id: &str, started_at: &str) -> Result<Reply, ApiError>;
    fn result(&self, id: &str, body: &Value) -> Result<Reply, ApiError>;
}

/// [`TaskApi`] over a [`Transport`].
pub struct Api<'a>(pub &'a dyn Transport);

impl TaskApi for Api<'_> {
    fn poll(&self) -> Result<PollReply, ApiError> {
        let response = self.0.post(POLL_PATH, &poll_body())?;
        parse_poll(&response.body).map_err(ApiError::InvalidResponse)
    }

    fn start(&self, id: &str, started_at: &str) -> Result<Reply, ApiError> {
        match final_or_retry(self.0.post(&start_path(id), &start_body(started_at)))? {
            Ok(response) => parse_start(&response.body).map_err(ApiError::InvalidResponse),
            Err(rejected) => Ok(rejected),
        }
    }

    fn result(&self, id: &str, body: &Value) -> Result<Reply, ApiError> {
        Ok(match final_or_retry(self.0.post(&result_path(id), body))? {
            Ok(_) => Reply::Accepted,
            Err(rejected) => rejected,
        })
    }
}

/// An answered request (`Ok(Ok)`), a refusal that is final (`Ok(Err)`), or an error to retry.
fn final_or_retry(
    sent: Result<ApiResponse, ApiError>,
) -> Result<Result<ApiResponse, Reply>, ApiError> {
    match sent {
        Ok(response) => Ok(Ok(response)),
        Err(ApiError::Rejected {
            status: 404 | 409 | 422,
            code,
            ..
        }) => Ok(Err(Reply::Rejected(crate::logging::sanitize(&code, 64)))),
        Err(e) => Err(e),
    }
}

/// `task-poll.request`.
pub fn poll_body() -> Value {
    json!({"schema_version": AGENT_SCHEMA_VERSION, "agent_version": AGENT_VERSION})
}

/// `task-start.request`.
pub fn start_body(started_at: &str) -> Value {
    json!({
        "schema_version": AGENT_SCHEMA_VERSION,
        "agent_version": AGENT_VERSION,
        "started_at": started_at,
    })
}

/// Reads `task-poll.response`.
pub fn parse_poll(body: &Value) -> Result<PollReply, String> {
    let object = body
        .as_object()
        .ok_or("the poll response is not an object")?;
    match object.get("task") {
        Some(Value::Null) => Ok(None),
        Some(task) => parse_task(task).map(Some),
        None => Err("the poll response has no task".into()),
    }
}

fn parse_task(task: &Value) -> Result<Delivered, String> {
    let object = task.as_object().ok_or("the task is not an object")?;
    let text = |name: &str| -> Result<String, String> {
        object
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("the task has no `{name}` string"))
    };
    let number = |name: &str| -> Result<u64, String> {
        object
            .get(name)
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("the task has no whole-number `{name}`"))
    };
    let id = text("id")?;
    if !super::ledger::is_task_id(&id) {
        return Err("the task id is not a lower-case UUID".into());
    }
    let task_type = text("type")?;
    if !super::catalog::is_type_id(&task_type) {
        return Err("the task type is not a type id".into());
    }
    let parameters = object
        .get("parameters")
        .filter(|p| p.is_object())
        .cloned()
        .ok_or("the task's parameters are not an object")?;
    let timeout_seconds = number("timeout_seconds")?;
    if !(1..=86_400).contains(&timeout_seconds) {
        return Err("the task's timeout_seconds is outside 1..=86400".into());
    }
    let catalog_version = u32::try_from(number("catalog_version")?)
        .map_err(|_| "the task's catalog_version is too large".to_owned())?;
    Ok(Delivered {
        id,
        task_type,
        parameters,
        timeout_seconds,
        catalog_version,
    })
}

/// Reads `task-start.response`: whether the agent may run the task.
pub fn parse_start(body: &Value) -> Result<Reply, String> {
    let run = body
        .get("run")
        .and_then(Value::as_bool)
        .ok_or("the start response has no `run` boolean")?;
    if run {
        return Ok(Reply::Accepted);
    }
    let state = body.get("state").and_then(Value::as_str).unwrap_or("");
    Ok(Reply::Rejected(crate::logging::sanitize(state, 32)))
}

/// What a result body says.
#[derive(Debug, Clone)]
pub struct ResultFields<'a> {
    pub outcome: Outcome,
    /// Required for `failed` and `refused`, absent otherwise.
    pub reason: Option<&'a str>,
    pub exit_status: Option<i32>,
    pub started_at: Option<String>,
    pub finished_at: String,
    pub output: String,
    pub output_truncated: bool,
    pub details: Map<String, Value>,
}

/// `task-result.request`, with a new `report_id`. The body is stored before it is first sent and sent
/// unchanged on every retry, so the `report_id` stays the same (P3-S04's idempotency).
pub fn result_body(fields: &ResultFields<'_>) -> Value {
    let report_id = crate::report::new_report_id().unwrap_or_else(|_| fallback_report_id());
    let mut body = Map::new();
    body.insert("schema_version".into(), json!(AGENT_SCHEMA_VERSION));
    body.insert("agent_version".into(), json!(AGENT_VERSION));
    body.insert("report_id".into(), json!(report_id));
    body.insert("outcome".into(), json!(fields.outcome.as_str()));
    let reason = match fields.outcome {
        Outcome::Failed | Outcome::Refused => fields.reason,
        _ => None,
    };
    body.insert("reason".into(), json!(reason));
    // The schema's range; a signal or anything odd is "no exit status".
    let exit_status = fields.exit_status.filter(|s| (0..=255).contains(s));
    body.insert("exit_status".into(), json!(exit_status));
    body.insert("started_at".into(), json!(fields.started_at));
    body.insert("finished_at".into(), json!(fields.finished_at));
    body.insert("details".into(), Value::Object(fields.details.clone()));
    body.insert("output".into(), json!(fields.output));
    body.insert("output_truncated".into(), json!(fields.output_truncated));
    Value::Object(body)
}

/// A report id when the kernel's random source fails: still a well-formed v4 UUID, from the clock.
fn fallback_report_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut bytes = nanos.to_be_bytes();
    bytes[0] ^= std::process::id() as u8;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let h = crate::release::hex(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// The outcome and reason a stored result body says.
pub fn outcome_of(body: &Value) -> Option<(Outcome, Option<String>)> {
    let outcome: Outcome = serde_json::from_value(body.get("outcome")?.clone()).ok()?;
    let reason = body
        .get("reason")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some((outcome, reason))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::contract::assert_conforms;
    use crate::report::tests::{FakeTransport, ok};

    fn example(schema: &str, kind: &str) -> Vec<(String, Value)> {
        let dir = crate::collect::contract::root()
            .join("examples/v1")
            .join(schema)
            .join(kind);
        let mut out: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| {
                let path = e.unwrap().path();
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                (
                    name,
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap(),
                )
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        assert!(!out.is_empty(), "no examples in {}", dir.display());
        out
    }

    #[test]
    fn requests_conform_to_the_contract() {
        assert_conforms("v1", "task-poll.request", &poll_body());
        assert_conforms(
            "v1",
            "task-start.request",
            &start_body("2026-01-01T12:00:00.000Z"),
        );
        let base = ResultFields {
            outcome: Outcome::Succeeded,
            reason: None,
            exit_status: Some(0),
            started_at: Some("2026-01-01T12:00:00.000Z".into()),
            finished_at: "2026-01-01T12:00:02.000Z".into(),
            output: "done\n".into(),
            output_truncated: false,
            details: Map::new(),
        };
        for (outcome, reason) in [
            (Outcome::Succeeded, None),
            (Outcome::Succeeded, Some("interrupted")),
            (Outcome::Failed, Some("interrupted")),
            (Outcome::Failed, Some("agent_error")),
            (Outcome::Refused, Some("not_supported")),
            (Outcome::Refused, Some("not_enabled_locally")),
            (Outcome::Refused, Some("unknown_type")),
            (Outcome::Refused, Some("invalid_params")),
            (Outcome::TimedOut, None),
            (Outcome::Cancelled, None),
        ] {
            for exit_status in [None, Some(0), Some(-9), Some(300)] {
                let body = result_body(&ResultFields {
                    outcome,
                    reason,
                    exit_status,
                    started_at: None,
                    ..base.clone()
                });
                assert_conforms("v1", "task-result.request", &body);
            }
        }
        // A new report id each time; a stored body keeps its own.
        assert_ne!(
            result_body(&base)["report_id"],
            result_body(&base)["report_id"]
        );
        let id = fallback_report_id();
        assert!(super::super::ledger::is_task_id(&id), "{id}");
    }

    #[test]
    fn every_poll_example_reads_as_the_contract_says() {
        for (name, body) in example("task-poll.response", "valid") {
            let reply = parse_poll(&body).unwrap_or_else(|e| panic!("{name}: {e}"));
            match &reply {
                None => assert_eq!(name, "no-task.json"),
                Some(task) => {
                    assert_eq!(task.id, body["task"]["id"], "{name}");
                    assert_eq!(task.task_type, body["task"]["type"], "{name}");
                    assert_eq!(task.parameters, body["task"]["parameters"], "{name}");
                    assert_eq!(
                        task.timeout_seconds, body["task"]["timeout_seconds"],
                        "{name}"
                    );
                }
            }
        }
        // Every invalid example is refused before it becomes a task, except the ones about parameter
        // values, which the executor's typed checks refuse (`invalid_params`, P3-A03).
        let caught_by_executor = [
            "parameter-name-uppercase.json",
            "parameter-too-long.json",
            "parameter-list.json",
            "parameter-object.json",
        ];
        for (name, body) in example("task-poll.response", "invalid") {
            if caught_by_executor.contains(&name.as_str()) {
                continue;
            }
            assert!(parse_poll(&body).is_err(), "{name} was read as a task");
        }
    }

    #[test]
    fn start_examples_say_whether_to_run() {
        for (name, body) in example("task-start.response", "valid") {
            let reply = parse_start(&body).unwrap();
            assert_eq!(reply == Reply::Accepted, body["run"] == true, "{name}");
        }
        assert!(parse_start(&json!({"id": "x", "state": "running"})).is_err());
        assert_eq!(
            parse_start(&json!({"state": "cancelled", "run": false})).unwrap(),
            Reply::Rejected("cancelled".into())
        );
    }

    #[test]
    fn requests_go_to_the_documented_paths_and_final_refusals_are_told_from_retries() {
        let id = "00000000-0000-4000-8000-0000000000a1";
        let transport = FakeTransport::new(vec![
            ok(json!({"task": null})),
            ok(json!({"id": id, "state": "running", "run": true})),
            Err(ApiError::Rejected {
                status: 409,
                code: "task_conflict".into(),
                message: String::new(),
                request_id: None,
            }),
            Err(ApiError::Server {
                status: 503,
                request_id: None,
            }),
            ok(json!({"task": {"id": "x"}})),
        ]);
        let api = Api(&transport);
        assert_eq!(api.poll().unwrap(), None);
        assert_eq!(
            api.start(id, "2026-01-01T12:00:00.000Z").unwrap(),
            Reply::Accepted
        );
        assert_eq!(
            api.result(id, &json!({})).unwrap(),
            Reply::Rejected("task_conflict".into())
        );
        assert!(api.result(id, &json!({})).is_err());
        assert!(matches!(api.poll(), Err(ApiError::InvalidResponse(_))));
        let paths: Vec<String> = transport.sent().into_iter().map(|(p, _)| p).collect();
        assert_eq!(
            paths,
            [
                POLL_PATH.to_owned(),
                format!("/api/v1/tasks/{id}/start"),
                format!("/api/v1/tasks/{id}/result"),
                format!("/api/v1/tasks/{id}/result"),
                POLL_PATH.to_owned(),
            ]
        );
        // Any 200 to a result is accepted: stored, a duplicate, or a late annotation.
        for (_, body) in example("task-result.response", "valid") {
            let transport = FakeTransport::new(vec![ok(body)]);
            assert_eq!(
                Api(&transport).result(id, &json!({})).unwrap(),
                Reply::Accepted
            );
        }
    }

    #[test]
    fn stored_results_say_their_outcome() {
        for (name, body) in example("task-result.request", "valid") {
            let (outcome, reason) = outcome_of(&body).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(outcome.as_str(), body["outcome"], "{name}");
            assert_eq!(reason.as_deref(), body["reason"].as_str(), "{name}");
        }
    }
}
