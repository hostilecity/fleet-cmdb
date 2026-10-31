//! Step 3 of `install` (enroll) and the credential check that opens step 4 (P1-A10, ADR 0017).
//!
//! - **Onboarding** (default): `POST /api/v1/onboarding` with the VM's facts, then the approval page, the
//!   user code, and a QR code are printed, and `POST /api/v1/onboarding/token` is polled at the server's
//!   interval (slower after a `429`, as in RFC 8628) with a countdown until it is approved, rejected,
//!   or expired, or the person presses Ctrl-C. Network errors while waiting are retried until the
//!   request expires.
//! - **Pre-registered token**: `POST /api/v1/enroll` with the one-time token.
//! - **Already enrolled**: the existing credential is kept.
//!
//! The config holding the credential is written only after the credential has been received, in one
//! atomic write with mode `0600`, so a rejection, an expiry, Ctrl-C, or a crash leaves the previous
//! config (or none) in place. The device code and the token are sent only in request bodies and are
//! never printed.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{Value, json};

use crate::client::{ApiError, ApiResponse, Client};
use crate::config::{Config, Credential};
use crate::report::{HEARTBEAT_PATH, HeartbeatRequest, rfc3339};
use crate::{AGENT_SCHEMA_VERSION, AGENT_VERSION};

use super::configfile::{self, Carried};
use super::fsx;
use super::preflight::Plan;
use super::qr;
use super::token::{DeviceCode, Token};
use super::ui::Ui;
use super::{Enrolled, Facts, Failure, Host, InstallError};

/// Longest wait between polls after network errors while waiting for approval.
const MAX_POLL_BACKOFF: Duration = Duration::from_secs(60);

fn server_error(what: impl Into<String>, next: impl Into<String>) -> InstallError {
    InstallError::new(Failure::Server, what, next)
}

fn with_request_id(error: &ApiError) -> String {
    error
        .request_id()
        .map(|id| format!(" (request id {id})"))
        .unwrap_or_default()
}

/// The failures every enrollment call shares: an old agent, throttling, an outage, an unexpected answer.
fn common_error(error: &ApiError, during: &str) -> InstallError {
    let id = with_request_id(error);
    match error {
        ApiError::AgentVersionUnsupported { message, .. } => server_error(
            format!(
                "the server does not accept this agent version ({AGENT_VERSION}): {message}{id}"
            ),
            "Download the current agent from the dashboard's install page and run its install command.",
        ),
        ApiError::RateLimited { retry_after, .. } => server_error(
            format!("the server is limiting {during} requests from this address{id}"),
            format!(
                "Wait {} and run the same command again. If many VMs are waiting, approve or reject the open requests in the dashboard first.",
                retry_after.map_or("a minute".to_owned(), |d| format!(
                    "{} seconds",
                    d.as_secs()
                ))
            ),
        ),
        ApiError::Transport(message) => server_error(
            format!("lost contact with the server during {during}: {message}"),
            "Check the network, then run the same command again.",
        ),
        ApiError::Server { status, .. } => server_error(
            format!("the server failed during {during} (HTTP {status}){id}"),
            "Try again in a few minutes; if it persists, check the server logs for the request id.",
        ),
        other => server_error(
            format!(
                "the server refused the {during} request (HTTP {}){id}",
                other.status()
            ),
            "Make sure this agent and the server are compatible versions (see the dashboard's install page), then run the same command again.",
        ),
    }
}

fn unexpected(during: &str, response: &ApiResponse) -> InstallError {
    server_error(
        format!(
            "the server sent an unexpected answer during {during} (HTTP {})",
            response.status
        ),
        "Make sure --server is the Fleet CMDB agent hostname and the server is up to date, then run the same command again.",
    )
}

/// The credential in a successful enrollment or approval answer, exactly as sent and in the format the
/// agent accepts, or an error that leaves every file as it was (review of #67). It is checked here,
/// before the config is written, because a malformed one would otherwise replace a working config with
/// one the service refuses; and it is never cleaned up or shortened, since a changed credential is a
/// wrong one.
fn received_credential(during: &str, response: &ApiResponse) -> Result<Credential, InstallError> {
    let credential = response.body["credential"]
        .as_str()
        .map(Credential::new)
        .filter(Credential::is_well_formed);
    credential.ok_or_else(|| {
        let mut error = unexpected(during, response);
        error.what.push_str(
            ": the credential is missing or not in the expected format, so nothing was saved and the existing config is unchanged",
        );
        error
    })
}

/// Text from the server that will be printed: control characters removed and the length bounded.
fn printable(value: &Value, max: usize) -> Option<String> {
    let text = crate::logging::sanitize(value.as_str()?, max);
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

pub fn enroll(
    host: &Host,
    plan: &Plan,
    token: Option<Token>,
    ui: &mut Ui,
) -> Result<Enrolled, InstallError> {
    let paths = &host.paths;
    let etc = paths.etc_dir();
    fsx::ensure_dir(&etc, 0o700, host.owner_uid)
        .map_err(|e| InstallError::failed(e.to_string()))?;
    // A run killed during a write may have left a temporary copy of the config, which holds a
    // credential; remove it.
    for name in ["config.toml", "ca.pem"] {
        fsx::remove_stale_temps(&etc, name)
            .map_err(|e| InstallError::failed(format!("cannot clean up {}: {e}", etc.display())))?;
    }

    if !plan.enroll_anew {
        let existing = plan
            .existing
            .as_ref()
            .expect("kept only when a valid config exists");
        ui.detail(&format!(
            "Already enrolled: keeping the existing credential (key id {}). Use --reenroll to enroll again.",
            existing.credential.key_id()
        ));
        let ca_file = install_ca(host, plan, ui)?;
        let config_written = if ca_file != existing.ca_file {
            write_config(
                host,
                &plan.server_url,
                &existing.credential,
                ca_file.as_deref(),
                &Carried::from(existing),
            )?;
            ui.detail(&format!("Updated ca_file in {}.", paths.config().display()));
            true
        } else {
            false
        };
        return Ok(Enrolled {
            config: reload(host)?,
            host_name: None,
            config_written,
            fresh: false,
        });
    }

    let client = Client::anonymous(
        &plan.server_url,
        plan.ca_for_run.as_deref(),
        &host.system_ca_bundle,
    )
    .map_err(|e| InstallError::new(Failure::Preflight, e.to_string(), "Pass a valid --ca-file."))?;
    let facts = Facts::collect(paths);
    let (credential, host_name) = match token {
        Some(token) => by_token(&client, &token, &facts, plan.existing.is_some(), ui)?,
        None => by_onboarding(host, &client, &facts, ui)?,
    };
    let ca_file = install_ca(host, plan, ui)?;
    let carried = plan
        .existing
        .as_ref()
        .map_or_else(Carried::none, Carried::from);
    write_config(
        host,
        &plan.server_url,
        &credential,
        ca_file.as_deref(),
        &carried,
    )?;
    ui.detail(&format!(
        "Saved the credential (key id {}) to {} (root only, mode 0600).",
        credential.key_id(),
        paths.config().display()
    ));
    Ok(Enrolled {
        config: reload(host)?,
        host_name,
        config_written: true,
        fresh: true,
    })
}

/// Copies `--ca-file` to `/etc/fleet-agent/ca.pem` and returns the `ca_file` the config should name.
fn install_ca(host: &Host, plan: &Plan, ui: &mut Ui) -> Result<Option<PathBuf>, InstallError> {
    let Some(source) = &plan.ca_source else {
        return Ok(plan.existing.as_ref().and_then(|c| c.ca_file.clone()));
    };
    let target = host.paths.ca();
    if !fsx::same_contents(source, &target).unwrap_or(false) {
        let mut file = std::fs::File::open(source)
            .map_err(|e| InstallError::failed(format!("cannot read {}: {e}", source.display())))?;
        fsx::write_atomic_from(&target, &mut file, 0o644)
            .map_err(|e| InstallError::failed(format!("cannot write {}: {e}", target.display())))?;
        ui.detail(&format!(
            "Copied the CA certificate to {}.",
            target.display()
        ));
    }
    Ok(Some(target))
}

fn write_config(
    host: &Host,
    server_url: &str,
    credential: &Credential,
    ca_file: Option<&Path>,
    carried: &Carried,
) -> Result<(), InstallError> {
    let path = host.paths.config();
    let text = configfile::render(server_url, credential, ca_file, carried).map_err(|e| {
        server_error(
            format!("cannot build the config: {e}"),
            "The server's answer was not usable. Run the same command again; if it fails again, report it with the server's version.",
        )
    })?;
    fsx::write_atomic(&path, text.as_bytes(), 0o600).map_err(|e| {
        InstallError::failed(format!(
            "cannot write {}: {e}. The credential was received but not saved, so it is lost; the old config, if any, is unchanged",
            path.display()
        ))
    })
}

/// Loads the config back exactly as the service will, so what was written is what runs.
fn reload(host: &Host) -> Result<Config, InstallError> {
    Config::load_as(&host.paths.config(), host.owner_uid)
        .map_err(|e| InstallError::failed(format!("the config just written cannot be loaded: {e}")))
}

fn by_token(
    client: &Client,
    token: &Token,
    facts: &Facts,
    enrolled_before: bool,
    ui: &mut Ui,
) -> Result<(Credential, Option<String>), InstallError> {
    ui.detail("Enrolling with the one-time token.");
    let body = json!({
        "schema_version": AGENT_SCHEMA_VERSION,
        "agent_version": AGENT_VERSION,
        "token": token.expose_secret(),
        "hostname": facts.hostname,
        "machine_id": facts.machine_id,
    });
    let unchanged = if enrolled_before {
        " This VM's existing enrollment is unchanged."
    } else {
        ""
    };
    match client.post_json("/api/v1/enroll", &body) {
        Ok(response) if response.status == 201 => {
            let credential = received_credential("enrollment", &response)?;
            let name = printable(&response.body["host_name"], 100);
            match &name {
                Some(name) => ui.detail(&format!("Enrolled as \"{name}\".")),
                None => ui.detail("Enrolled."),
            }
            Ok((credential, name))
        }
        Ok(response) => Err(unexpected("enrollment", &response)),
        Err(error @ ApiError::Rejected { status: 410, .. }) => Err(InstallError::new(
            Failure::Expired,
            format!(
                "the server refused the enrollment token: it is invalid, expired, or already used{}.{unchanged}",
                with_request_id(&error)
            ),
            "Issue a new one-time token for this host in the dashboard (host page, Re-enroll), then run the command again with it. Or run without a token to enroll by approval instead.",
        )),
        Err(ApiError::Transport(message)) => Err(server_error(
            format!("lost contact with the server while enrolling: {message}.{unchanged}"),
            "Run the same command again. If the token was used before the connection dropped, it no longer works: issue a new one in the dashboard.",
        )),
        Err(error) => Err(common_error(&error, "enrollment")),
    }
}

struct Onboarding {
    device_code: DeviceCode,
    user_code: String,
    page: String,
    expires_in: Duration,
    interval: Duration,
}

fn parse_onboarding(response: &ApiResponse) -> Option<Onboarding> {
    let body = &response.body;
    let device_code = body["device_code"].as_str().filter(|c| {
        (43..=128).contains(&c.len())
            && c.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    })?;
    let user_code = body["user_code"].as_str().filter(|c| {
        let alphabet =
            |s: &str| s.len() == 4 && s.chars().all(|c| "BCDFGHJKLMNPQRSTVWXZ".contains(c));
        c.split_once('-')
            .is_some_and(|(a, b)| alphabet(a) && alphabet(b))
    })?;
    // Printed for a person to open: printable ASCII only, so it cannot carry terminal escapes.
    let page = body["verification_uri_complete"].as_str().filter(|u| {
        u.len() <= 2048
            && (u.starts_with("https://") || u.starts_with("http://"))
            && u.bytes().all(|b| b.is_ascii_graphic())
    })?;
    let expires_in = body["expires_in"]
        .as_u64()
        .filter(|s| (1..=86_400).contains(s))?;
    let interval = body["interval"]
        .as_u64()
        .filter(|s| (1..=300).contains(s))?;
    Some(Onboarding {
        device_code: DeviceCode::new(device_code.to_owned()),
        user_code: user_code.to_owned(),
        page: page.to_owned(),
        expires_in: Duration::from_secs(expires_in),
        interval: Duration::from_secs(interval),
    })
}

fn by_onboarding(
    host: &Host,
    client: &Client,
    facts: &Facts,
    ui: &mut Ui,
) -> Result<(Credential, Option<String>), InstallError> {
    let body = json!({
        "schema_version": AGENT_SCHEMA_VERSION,
        "agent_version": AGENT_VERSION,
        "hostname": facts.hostname,
        "machine_id": facts.machine_id,
        "os": facts.os,
    });
    let started = match client.post_json("/api/v1/onboarding", &body) {
        Ok(response) if response.status == 201 => {
            parse_onboarding(&response).ok_or_else(|| unexpected("onboarding", &response))?
        }
        Ok(response) => return Err(unexpected("onboarding", &response)),
        Err(error @ ApiError::RateLimited { .. }) => {
            let mut e = common_error(&error, "onboarding");
            e.what
                .push_str(", or too many onboarding requests are already open");
            return Err(e);
        }
        Err(error) => return Err(common_error(&error, "onboarding")),
    };
    let deadline = host.clock.now() + started.expires_in;
    ui.approval(
        &started.page,
        &started.user_code,
        started.expires_in,
        qr::render(&started.page),
    );
    let (credential, name) = poll(host, client, &started, deadline, ui)?;
    match &name {
        Some(name) => ui.detail(&format!("Approved as \"{name}\".")),
        None => ui.detail("Approved."),
    }
    Ok((credential, name))
}

enum Poll {
    Pending,
    Approved(Credential, Option<String>),
}

fn poll(
    host: &Host,
    client: &Client,
    started: &Onboarding,
    deadline: Instant,
    ui: &mut Ui,
) -> Result<(Credential, Option<String>), InstallError> {
    let body = json!({
        "schema_version": AGENT_SCHEMA_VERSION,
        "agent_version": AGENT_VERSION,
        "device_code": started.device_code.expose_secret(),
    });
    let minutes = started.expires_in.as_secs().div_ceil(60);
    let expired = || {
        InstallError::new(
            Failure::Expired,
            "the onboarding request expired before an operator approved it; nothing was enrolled",
            format!(
                "Run the same command again to start a new request, and approve it in the dashboard within {minutes} minutes."
            ),
        )
    };
    let mut interval = started.interval;
    let mut next_poll = host.clock.now() + interval;
    let mut failures: u32 = 0;
    loop {
        let now = host.clock.now();
        if now >= deadline {
            return Err(expired());
        }
        if now >= next_poll {
            let result = match client.post_json("/api/v1/onboarding/token", &body) {
                Ok(response) => match (response.status, response.body["status"].as_str()) {
                    (202, Some("pending")) => Ok(Poll::Pending),
                    (201, Some("approved")) => {
                        let credential = received_credential("onboarding", &response)?;
                        Ok(Poll::Approved(
                            credential,
                            printable(&response.body["host_name"], 100),
                        ))
                    }
                    _ => return Err(unexpected("onboarding", &response)),
                },
                Err(error) => Err(error),
            };
            let now = host.clock.now();
            match result {
                Ok(Poll::Approved(credential, name)) => {
                    ui.countdown(deadline.saturating_duration_since(now));
                    return Ok((credential, name));
                }
                Ok(Poll::Pending) => {
                    if failures > 0 {
                        ui.detail("Back in contact with the server; still waiting for approval.");
                    }
                    failures = 0;
                    next_poll = now + interval;
                }
                Err(ApiError::Forbidden { code, .. }) if code == "onboarding_rejected" => {
                    return Err(InstallError::new(
                        Failure::Rejected,
                        "an operator rejected this VM's onboarding request in the dashboard; nothing was enrolled",
                        "If that was a mistake, run the same command again for a new request and ask the operator to approve the code it shows.",
                    ));
                }
                Err(ApiError::Rejected { status: 410, .. }) => return Err(expired()),
                Err(ApiError::RateLimited { retry_after, .. }) => {
                    // RFC 8628 slow_down: poll 5 seconds less often from now on.
                    interval = (interval + Duration::from_secs(5)).min(Duration::from_secs(300));
                    next_poll = now + retry_after.unwrap_or_default().max(interval);
                }
                Err(
                    error @ (ApiError::Transport(_)
                    | ApiError::Server { .. }
                    | ApiError::InvalidResponse(_)),
                ) => {
                    if failures == 0 {
                        let reason = match &error {
                            ApiError::Transport(message) => message.clone(),
                            other => format!("HTTP {}", other.status()),
                        };
                        ui.warn(&format!(
                            "cannot reach the server to check for approval ({reason}); still trying until the request expires"
                        ));
                    }
                    failures = failures.saturating_add(1);
                    let backoff = interval
                        .saturating_mul(1 << failures.min(4))
                        .min(MAX_POLL_BACKOFF);
                    next_poll = now + backoff;
                }
                Err(error) => return Err(common_error(&error, "onboarding")),
            }
        }
        let now = host.clock.now();
        ui.countdown(deadline.saturating_duration_since(now));
        let wait = next_poll
            .saturating_duration_since(now)
            .min(deadline.saturating_duration_since(now))
            .min(Duration::from_secs(1))
            .max(Duration::from_millis(10));
        if host.clock.sleep(wait) {
            return Err(InstallError::new(
                Failure::Interrupted,
                "cancelled while waiting for approval; nothing was enrolled and no credential was written",
                "The request expires on its own (an operator can also reject it in the dashboard). Run the same command again to start over.",
            ));
        }
    }
}

/// Sends one heartbeat with the config as written, proving the server accepts the credential before the
/// service is (re)started. Retries briefly on network and server errors.
pub fn confirm(
    host: &Host,
    enrolled: &Enrolled,
    started: Instant,
    ui: &mut Ui,
) -> Result<(), InstallError> {
    let config = &enrolled.config;
    let client = Client::with_system_bundle(config, &host.system_ca_bundle).map_err(|e| {
        InstallError::failed(format!(
            "cannot use the trusted certificates in the config: {e}"
        ))
    })?;
    let key_id = config.credential.key_id();
    // The same sysctl read as the service's heartbeat, not a whole collection (review of #67).
    let hostname = crate::collect::hostname_under(&host.paths.root);
    let waits = [
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(10),
    ];
    let mut attempt = 0;
    loop {
        // The service's own request type, so the contract has one definition (review of #67).
        let body = HeartbeatRequest {
            schema_version: AGENT_SCHEMA_VERSION,
            agent_version: AGENT_VERSION,
            hostname: hostname.clone(),
            uptime_seconds: host
                .clock
                .now()
                .saturating_duration_since(started)
                .as_secs(),
            agent_time: rfc3339(SystemTime::now()),
        };
        let error = match client.post_json(HEARTBEAT_PATH, &body) {
            Ok(response) if response.status == 200 => {
                ui.detail("The server accepted a heartbeat with this VM's credential.");
                return Ok(());
            }
            Ok(response) => return Err(unexpected("the first heartbeat", &response)),
            Err(error) => error,
        };
        let id = with_request_id(&error);
        let reenroll = "Run `sudo fleet-agent install --reenroll` and approve the request in the dashboard, or `sudo fleet-agent install --token` with a new one-time token.";
        match &error {
            ApiError::Unauthorized { .. } if !enrolled.fresh => {
                return Err(InstallError::new(
                    Failure::Rejected,
                    format!(
                        "the server no longer accepts this VM's credential (key id {key_id}): it was revoked or the host was retired{id}"
                    ),
                    reenroll,
                ));
            }
            ApiError::ReenrollmentRequired { .. } => {
                return Err(InstallError::new(
                    Failure::Rejected,
                    format!(
                        "this host is being re-enrolled, so its current credential (key id {key_id}) can no longer report{id}"
                    ),
                    reenroll,
                ));
            }
            ApiError::Forbidden { code, .. } => {
                return Err(InstallError::new(
                    Failure::Rejected,
                    format!("the server refused this host's heartbeat ({code}){id}"),
                    format!("Check the host's state in the dashboard. {reenroll}"),
                ));
            }
            ApiError::Transport(_)
            | ApiError::Server { .. }
            | ApiError::InvalidResponse(_)
            | ApiError::RateLimited { .. }
                if attempt < waits.len() =>
            {
                let wait = match &error {
                    ApiError::RateLimited {
                        retry_after: Some(after),
                        ..
                    } => (*after).min(Duration::from_secs(60)),
                    _ => waits[attempt],
                };
                attempt += 1;
                if host.clock.sleep(wait) {
                    return Err(super::interrupted());
                }
            }
            ApiError::Transport(message) => {
                return Err(server_error(
                    format!("enrolled, but could not confirm with a heartbeat: {message}"),
                    "The credential is saved. Run the same command again once the server is reachable; it keeps the credential and finishes the install.",
                ));
            }
            other => {
                let mut e = common_error(other, "the first heartbeat");
                e.next = format!(
                    "The credential is saved; running the same command again keeps it. {}",
                    e.next
                );
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onboarding_responses_are_checked_before_anything_is_shown() {
        let good = json!({
            "device_code": "EXAMPLE-device-code-000000000000000000000000000",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://fleet.example.lan/onboard",
            "verification_uri_complete": "https://fleet.example.lan/onboard/WDJB-MJHT",
            "expires_in": 600,
            "interval": 5,
            "server_time": "2026-01-01T12:00:00Z"
        });
        let response = |body: Value| ApiResponse {
            status: 201,
            body,
            request_id: None,
        };
        assert!(parse_onboarding(&response(good.clone())).is_some());
        for (key, bad) in [
            ("user_code", json!("WDJB-MJHA")),
            ("user_code", json!("\u{1b}[2J")),
            (
                "verification_uri_complete",
                json!("https://fleet.example.lan/\u{1b}[31m"),
            ),
            ("verification_uri_complete", json!("javascript:alert(1)")),
            ("device_code", json!("short")),
            ("expires_in", json!(0)),
            ("interval", json!(100000)),
        ] {
            let mut body = good.clone();
            body[key] = bad;
            assert!(parse_onboarding(&response(body)).is_none(), "{key}");
        }
    }
}
