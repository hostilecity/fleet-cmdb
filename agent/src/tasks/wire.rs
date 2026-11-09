//! The task API as the agent speaks it (P3-S03, P3-S04): `POST /api/v1/tasks/poll`,
//! `POST /api/v1/tasks/:id/start`, and `POST /api/v1/tasks/:id/result`. Schemas and examples are in
//! `docs/api/schemas/v1` and `docs/api/examples/v1`; the tests check every request against them and
//! read every example response.
//!
//! The poller sees only [`TaskApi`]. A response this agent cannot read is never a task: a poll reply
//! whose task is malformed is treated as a failed request, so nothing malformed is recorded or run.

use serde_json::{Map, Value, json};

use super::executor::Delivered;
use super::ledger::Outcome;
use crate::client::ApiError;
use crate::report::Transport;

pub const POLL_PATH: &str = "/api/v1/tasks/poll";

pub fn start_path(id: &str) -> String {
    format!("/api/v1/tasks/{id}/start")
}

pub fn result_path(id: &str) -> String {
    format!("/api/v1/tasks/{id}/result")
}

/// What a poll returned.
#[derive(Debug, Clone, PartialEq)]
pub struct PollReply {
    pub task: Option<Delivered>,
    /// The server's poll interval hint, before clamping.
    pub poll_after_seconds: Option<u64>,
}

/// What `start` or `result` returned, when the request itself got an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Accepted,
    /// Refused for good (sending it again cannot help), with the error code.
    Rejected(String),
}

/// The task endpoints. [`Api`] over the agent's [`Transport`] in production; a fake in tests.
pub trait TaskApi {
    fn poll(&self) -> Result<PollReply, ApiError>;
    fn start(&self, id: &str) -> Result<Reply, ApiError>;
    fn result(&self, id: &str, body: &Value) -> Result<Reply, ApiError>;
}

/// [`TaskApi`] over a [`Transport`].
pub struct Api<'a>(pub &'a dyn Transport);

impl TaskApi for Api<'_> {
    fn poll(&self) -> Result<PollReply, ApiError> {
        let response = self.0.post(POLL_PATH, &poll_body())?;
        parse_poll(&response.body).map_err(ApiError::InvalidResponse)
    }

    fn start(&self, id: &str) -> Result<Reply, ApiError> {
        final_or_retry(self.0.post(&start_path(id), &json!({})))
    }

    fn result(&self, id: &str, body: &Value) -> Result<Reply, ApiError> {
        final_or_retry(self.0.post(&result_path(id), body))
    }
}

/// An accepted request, a refusal that is final, or an error to retry.
fn final_or_retry(sent: Result<crate::client::ApiResponse, ApiError>) -> Result<Reply, ApiError> {
    match sent {
        Ok(_) => Ok(Reply::Accepted),
        Err(ApiError::Rejected {
            status: 404 | 409 | 410 | 422,
            code,
            ..
        }) => Ok(Reply::Rejected(crate::logging::sanitize(&code, 64))),
        Err(e) => Err(e),
    }
}

/// `tasks-poll.request`.
pub fn poll_body() -> Value {
    json!({
        "schema_version": crate::AGENT_SCHEMA_VERSION,
        "agent_version": crate::AGENT_VERSION,
    })
}

/// Reads `tasks-poll.response`.
pub fn parse_poll(body: &Value) -> Result<PollReply, String> {
    let object = body
        .as_object()
        .ok_or("the poll response is not an object")?;
    let poll_after_seconds = match object.get("poll_after_seconds") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            v.as_u64()
                .ok_or("poll_after_seconds is not a whole number")?,
        ),
    };
    let task = match object.get("task") {
        None | Some(Value::Null) => None,
        Some(task) => Some(parse_task(task)?),
    };
    Ok(PollReply {
        task,
        poll_after_seconds,
    })
}

fn parse_task(task: &Value) -> Result<Delivered, String> {
    let object = task.as_object().ok_or("the task is not an object")?;
    let text = |name: &str| -> Result<String, String> {
        object
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("the task has no {name} string"))
    };
    let parameters = object
        .get("parameters")
        .filter(|p| p.is_object())
        .cloned()
        .ok_or("the task's parameters are not an object")?;
    let catalog_version = object
        .get("catalog_version")
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or("the task has no catalog_version")?;
    let deadline = match object.get("deadline") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            v.as_str()
                .ok_or("the task's deadline is not a string")?
                .to_owned(),
        ),
    };
    let id = text("id")?;
    if !super::ledger::is_task_id(&id) {
        return Err("the task id is not a lower-case UUID".into());
    }
    let task_type = text("type")?;
    if !super::catalog::is_type_id(&task_type) {
        return Err("the task type is not a type id".into());
    }
    Ok(Delivered {
        id,
        task_type,
        parameters,
        deadline,
        catalog_version,
    })
}

/// What a result body says.
#[derive(Debug, Clone)]
pub struct ResultFields<'a> {
    pub outcome: Outcome,
    pub reason: Option<&'a str>,
    pub exit_status: Option<i32>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub output: String,
    pub output_truncated: bool,
    pub details: Map<String, Value>,
}

/// `tasks-result.request`.
pub fn result_body(fields: &ResultFields<'_>) -> Value {
    let mut body = Map::new();
    body.insert("schema_version".into(), json!(crate::AGENT_SCHEMA_VERSION));
    body.insert("outcome".into(), json!(fields.outcome.as_str()));
    if let Some(reason) = fields.reason {
        body.insert("reason".into(), json!(reason));
    }
    if let Some(status) = fields.exit_status {
        body.insert("exit_status".into(), json!(status));
    }
    if let Some(at) = &fields.started_at {
        body.insert("started_at".into(), json!(at));
    }
    if let Some(at) = &fields.finished_at {
        body.insert("finished_at".into(), json!(at));
    }
    body.insert("output".into(), json!(fields.output));
    body.insert("output_truncated".into(), json!(fields.output_truncated));
    body.insert("details".into(), Value::Object(fields.details.clone()));
    Value::Object(body)
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
