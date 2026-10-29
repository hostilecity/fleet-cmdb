//! HTTPS client for the agent API (`/api/v1`, DEC-08, P1-A02).
//!
//! - TLS through `rustls` (no OpenSSL), trusting the Debian system roots plus the optional `ca_file`
//!   from [`crate::config`]. There is no code path that disables certificate verification (NFR-1).
//! - Sends `Authorization: Bearer <credential>` and `User-Agent: fleet-agent/<version>` on every
//!   request. Redirects are not followed, so the credential only ever goes to the configured host.
//! - Maps the documented error envelope (`docs/api/README.md`) to [`ApiError`].
//! - Bounded: connect and overall request timeouts, and a maximum response size.
//! - One [`ureq::Agent`] per client, so connections are reused between requests.
//!
//! Retry and backoff are in [`crate::retry`].

use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use ureq::http::{Response, StatusCode};
use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig, TlsProvider};

use crate::AGENT_VERSION;
use crate::config::{Config, Credential};

/// Debian's system trust store (DEC-01), maintained by the `ca-certificates` package.
pub const SYSTEM_CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

/// Largest successful response body the agent reads. Heartbeat and inventory responses are tiny.
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
/// Largest error body the agent reads; the envelope's message is at most 1024 characters.
const MAX_ERROR_BYTES: u64 = 64 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Why the client could not be built. Each message says what to fix.
#[derive(Debug, PartialEq, Eq)]
pub enum TrustError {
    /// The `ca_file` from the config could not be read or holds no certificate.
    CaFile(String),
    /// Neither the system store nor a `ca_file` provided any certificate.
    NoRoots,
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaFile(message) => f.write_str(message),
            Self::NoRoots => write!(
                f,
                "no trusted certificate authorities: {SYSTEM_CA_BUNDLE} is missing or empty and no `ca_file` is set; install the ca-certificates package"
            ),
        }
    }
}

impl std::error::Error for TrustError {}

/// The roots the agent trusts: every certificate in `system_bundle` (if present) plus every
/// certificate in `ca_file` (if configured, and then required to exist and hold one).
pub fn trust_roots(
    system_bundle: &Path,
    ca_file: Option<&Path>,
) -> Result<Vec<Certificate<'static>>, TrustError> {
    let mut roots = match fs::read(system_bundle) {
        Ok(pem) => pem_certificates(&pem),
        Err(_) => Vec::new(),
    };
    if let Some(path) = ca_file {
        let pem = fs::read(path).map_err(|e| {
            TrustError::CaFile(format!("cannot read `ca_file` {}: {e}", path.display()))
        })?;
        let extra = pem_certificates(&pem);
        if extra.is_empty() {
            return Err(TrustError::CaFile(format!(
                "`ca_file` {} contains no PEM certificate (expected -----BEGIN CERTIFICATE-----)",
                path.display()
            )));
        }
        roots.extend(extra);
    }
    if roots.is_empty() {
        return Err(TrustError::NoRoots);
    }
    Ok(roots)
}

fn pem_certificates(pem: &[u8]) -> Vec<Certificate<'static>> {
    ureq::tls::parse_pem(pem)
        .filter_map(|item| match item {
            Ok(PemItem::Certificate(cert)) => Some(cert),
            _ => None,
        })
        .collect()
}

/// A failed API call, mapped from the HTTP status and the error envelope
/// `{"error": {"code", "message", "request_id"}}` (DEC-08). Unknown codes are treated by status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// The server could not be reached, TLS failed (including an untrusted certificate), or the
    /// request timed out.
    Transport(String),
    /// `401 unauthorized`: the credential is missing, unknown, revoked, or the host is retired.
    Unauthorized { request_id: Option<String> },
    /// `403 reenrollment_required`, or any response with `Fleet-Enrollment-State: pending`: an
    /// operator issued a new enrollment token, so this host must be re-enrolled.
    ReenrollmentRequired { request_id: Option<String> },
    /// Any other `403`, for example `host_not_active`.
    Forbidden {
        code: String,
        request_id: Option<String>,
    },
    /// `413 payload_too_large`.
    PayloadTooLarge { request_id: Option<String> },
    /// `426 agent_version_unsupported`: this agent is older than the server's minimum.
    AgentVersionUnsupported {
        message: String,
        request_id: Option<String>,
    },
    /// `429 rate_limited`, with the `Retry-After` delay when the server sent one in seconds.
    RateLimited {
        retry_after: Option<Duration>,
        request_id: Option<String>,
    },
    /// Any `5xx`.
    Server {
        status: u16,
        request_id: Option<String>,
    },
    /// Any other unsuccessful status, for example `400 validation_failed` or `404 not_found`.
    Rejected {
        status: u16,
        code: String,
        message: String,
        request_id: Option<String>,
    },
    /// A successful status with a body that is too large or not JSON.
    InvalidResponse(String),
}

impl ApiError {
    /// The request id the server gave, to quote when asking for help (NFR-4).
    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::Unauthorized { request_id }
            | Self::ReenrollmentRequired { request_id }
            | Self::Forbidden { request_id, .. }
            | Self::PayloadTooLarge { request_id }
            | Self::AgentVersionUnsupported { request_id, .. }
            | Self::RateLimited { request_id, .. }
            | Self::Server { request_id, .. }
            | Self::Rejected { request_id, .. } => request_id.as_deref(),
            Self::Transport(_) | Self::InvalidResponse(_) => None,
        }
    }

    /// The HTTP status, or 0 when no response arrived.
    pub fn status(&self) -> u16 {
        match self {
            Self::Transport(_) | Self::InvalidResponse(_) => 0,
            Self::Unauthorized { .. } => 401,
            Self::ReenrollmentRequired { .. } | Self::Forbidden { .. } => 403,
            Self::PayloadTooLarge { .. } => 413,
            Self::AgentVersionUnsupported { .. } => 426,
            Self::RateLimited { .. } => 429,
            Self::Server { status, .. } | Self::Rejected { status, .. } => *status,
        }
    }
}

/// A successful response.
#[derive(Debug, Clone, PartialEq)]
pub struct ApiResponse {
    pub status: u16,
    /// The JSON body, or `Null` for an empty body.
    pub body: serde_json::Value,
    pub request_id: Option<String>,
}

/// The agent API client. Cheap to share by reference; reuses connections.
pub struct Client {
    agent: ureq::Agent,
    server_url: String,
    credential: Credential,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("server_url", &self.server_url)
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Builds a client from a validated config, trusting the system roots plus `ca_file`.
    pub fn new(config: &Config) -> Result<Self, TrustError> {
        Self::with_system_bundle(config, Path::new(SYSTEM_CA_BUNDLE))
    }

    /// As [`Client::new`], with the system bundle path given (for tests).
    pub fn with_system_bundle(config: &Config, system_bundle: &Path) -> Result<Self, TrustError> {
        let roots = trust_roots(system_bundle, config.ca_file.as_deref())?;
        // Verification is always on: the agent never calls `disable_verification`.
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .root_certs(RootCerts::Specific(Arc::new(roots)))
            .build();
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .https_only(true)
            .max_redirects(0)
            .proxy(None)
            .http_status_as_error(false)
            .user_agent(format!("fleet-agent/{AGENT_VERSION}"))
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(REQUEST_TIMEOUT))
            .build()
            .into();
        Ok(Self {
            agent,
            server_url: config.server_url.clone(),
            credential: config.credential.clone(),
        })
    }

    /// The full URL for an API path such as `/api/v1/heartbeat`.
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server_url)
    }

    /// POSTs `body` as JSON to `path` (for example `/api/v1/heartbeat`).
    pub fn post_json<T: Serialize>(&self, path: &str, body: &T) -> Result<ApiResponse, ApiError> {
        let bytes = serde_json::to_vec(body)
            .map_err(|e| ApiError::InvalidResponse(format!("cannot encode request: {e}")))?;
        let response = self
            .agent
            .post(self.url(path))
            .header(
                "Authorization",
                format!("Bearer {}", self.credential.expose_secret()),
            )
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .send(&bytes[..])
            .map_err(|e| ApiError::Transport(transport_message(&e)))?;
        read_response(response)
    }
}

/// Describes a transport failure without quoting request headers (ureq's errors never contain them).
fn transport_message(error: &ureq::Error) -> String {
    crate::logging::sanitize(&error.to_string(), 512)
}

fn header(response: &Response<ureq::Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|v| crate::logging::sanitize(v.trim(), 255))
        .filter(|v| !v.is_empty())
}

/// Parses `Retry-After` in delta-seconds form. The HTTP-date form is not used by the server and is
/// ignored, which leaves the normal backoff in charge.
fn retry_after(response: &Response<ureq::Body>) -> Option<Duration> {
    header(response, "Retry-After")?
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

#[derive(Default)]
struct Envelope {
    code: Option<String>,
    message: Option<String>,
    request_id: Option<String>,
}

fn envelope(body: &[u8]) -> Envelope {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Envelope::default();
    };
    let field = |name: &str| {
        value["error"][name]
            .as_str()
            .map(|s| crate::logging::sanitize(s, 1024))
    };
    Envelope {
        code: field("code"),
        message: field("message"),
        request_id: field("request_id"),
    }
}

fn read_response(mut response: Response<ureq::Body>) -> Result<ApiResponse, ApiError> {
    let status = response.status();
    let header_request_id = header(&response, "X-Request-Id");

    if status.is_success() {
        let bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_vec()
            .map_err(|e| ApiError::InvalidResponse(transport_message(&e)))?;
        let body = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .map_err(|e| ApiError::InvalidResponse(format!("response is not JSON: {e}")))?
        };
        return Ok(ApiResponse {
            status: status.as_u16(),
            body,
            request_id: header_request_id,
        });
    }

    let pending = header(&response, "Fleet-Enrollment-State")
        .is_some_and(|v| v.eq_ignore_ascii_case("pending"));
    let retry_after = retry_after(&response);
    // An unreadable or oversized error body still maps by status.
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_ERROR_BYTES)
        .read_to_vec()
        .unwrap_or_default();
    let envelope = envelope(&body);
    let request_id = header_request_id.or(envelope.request_id);
    let code = envelope.code.unwrap_or_default();

    Err(match status {
        _ if pending || code == "reenrollment_required" => {
            ApiError::ReenrollmentRequired { request_id }
        }
        StatusCode::UNAUTHORIZED => ApiError::Unauthorized { request_id },
        StatusCode::FORBIDDEN => ApiError::Forbidden { code, request_id },
        StatusCode::PAYLOAD_TOO_LARGE => ApiError::PayloadTooLarge { request_id },
        StatusCode::UPGRADE_REQUIRED => ApiError::AgentVersionUnsupported {
            message: envelope.message.unwrap_or_default(),
            request_id,
        },
        StatusCode::TOO_MANY_REQUESTS => ApiError::RateLimited {
            retry_after,
            request_id,
        },
        s if s.is_server_error() => ApiError::Server {
            status: s.as_u16(),
            request_id,
        },
        s => ApiError::Rejected {
            status: s.as_u16(),
            code,
            message: envelope.message.unwrap_or_default(),
            request_id,
        },
    })
}

/// Reports whether an I/O error came from TLS certificate verification (used by tests).
#[cfg(test)]
fn is_certificate_error(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("certificate") || m.contains("unknownissuer") || m.contains("unknown issuer")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::tests as cfg;
    use crate::test_support::{TempDir, TestPki, TlsServer};

    fn config_for(server: &TlsServer, ca_file: Option<&Path>) -> Config {
        let mut text = format!(
            "server_url = \"https://localhost:{}\"\ncredential = \"{}\"\n",
            server.port,
            cfg::CREDENTIAL
        );
        if let Some(ca) = ca_file {
            text.push_str(&format!("ca_file = \"{}\"\n", ca.display()));
        }
        Config::from_toml(&text).unwrap()
    }

    /// A client that trusts only the test CA (no system roots), talking to `server`.
    pub fn trusting_client(server: &TlsServer, pki: &TestPki, dir: &TempDir) -> Client {
        let ca = dir.write("ca.pem", &pki.ca_pem);
        Client::with_system_bundle(&config_for(server, Some(&ca)), &dir.path("absent.pem")).unwrap()
    }

    fn response(status: &str, headers: &[&str], body: &str) -> String {
        let mut text = format!("HTTP/1.1 {status}\r\n");
        for h in headers {
            text.push_str(h);
            text.push_str("\r\n");
        }
        text.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ));
        text
    }

    fn error_body(code: &str, message: &str) -> String {
        format!(
            r#"{{"error":{{"code":"{code}","message":"{message}","request_id":"00000000-0000-4000-8000-000000000001"}}}}"#
        )
    }

    /// Sends one heartbeat-shaped request to a server that answers `reply`.
    fn call(reply: String) -> (Result<ApiResponse, ApiError>, String) {
        let pki = TestPki::generate();
        let dir = TempDir::new();
        let server = TlsServer::start(&pki, vec![reply]);
        let client = trusting_client(&server, &pki, &dir);
        let result = client.post_json("/api/v1/heartbeat", &serde_json::json!({"x": 1}));
        let requests = server.finish();
        (result, requests.into_iter().next().unwrap_or_default())
    }

    #[test]
    fn sends_bearer_credential_user_agent_and_json() {
        let (result, request) = call(response(
            "200 OK",
            &["X-Request-Id: req-1"],
            r#"{"server_time":"2026-01-01T12:00:00Z","directives":[]}"#,
        ));
        let ok = result.unwrap();
        assert_eq!(ok.status, 200);
        assert_eq!(ok.body["server_time"], "2026-01-01T12:00:00Z");
        assert_eq!(ok.request_id.as_deref(), Some("req-1"));
        let lower = request.to_ascii_lowercase();
        assert!(
            request.starts_with("POST /api/v1/heartbeat HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(lower.contains(&format!(
            "authorization: bearer {}",
            cfg::CREDENTIAL.to_ascii_lowercase()
        )));
        assert!(lower.contains(&format!("user-agent: fleet-agent/{AGENT_VERSION}")));
        assert!(lower.contains("content-type: application/json"));
        assert!(request.ends_with(r#"{"x":1}"#));
    }

    #[test]
    fn untrusted_certificate_is_refused() {
        // The server's chain is from a CA the client does not trust: once with the real system
        // store, once with only an unrelated private CA configured as `ca_file`.
        let pki = TestPki::generate();
        let other = TestPki::generate();
        let dir = TempDir::new();
        let other_ca = dir.write("other-ca.pem", &other.ca_pem);
        for (system, ca_file) in [
            (Path::new(SYSTEM_CA_BUNDLE).to_owned(), None),
            (dir.path("absent.pem"), Some(other_ca.as_path())),
        ] {
            if ca_file.is_none() && !system.exists() {
                continue; // no system store on this machine; the second case still runs
            }
            let server = TlsServer::start(&pki, vec![response("200 OK", &[], "{}")]);
            let client =
                Client::with_system_bundle(&config_for(&server, ca_file), &system).unwrap();
            let result = client.post_json("/api/v1/heartbeat", &serde_json::json!({}));
            let requests = server.finish();
            match result {
                Err(ApiError::Transport(message)) => {
                    assert!(is_certificate_error(&message), "{message}")
                }
                other => panic!("untrusted server was accepted: {other:?}"),
            }
            assert!(
                requests.is_empty(),
                "a request reached the untrusted server"
            );
        }
    }

    #[test]
    fn missing_or_empty_ca_file_is_an_error() {
        let dir = TempDir::new();
        let absent = dir.path("absent.pem");
        let error = trust_roots(&absent, Some(&dir.path("nope.pem"))).unwrap_err();
        assert!(
            error.to_string().contains("cannot read `ca_file`"),
            "{error}"
        );
        let empty = dir.write("empty.pem", "not a certificate\n");
        let error = trust_roots(&absent, Some(&empty)).unwrap_err();
        assert!(
            error.to_string().contains("contains no PEM certificate"),
            "{error}"
        );
        assert_eq!(trust_roots(&absent, None).unwrap_err(), TrustError::NoRoots);
    }

    #[test]
    fn maps_401() {
        let (result, _) = call(response(
            "401 Unauthorized",
            &[],
            &error_body("unauthorized", "no"),
        ));
        assert_eq!(
            result.unwrap_err(),
            ApiError::Unauthorized {
                request_id: Some("00000000-0000-4000-8000-000000000001".into())
            }
        );
    }

    #[test]
    fn maps_403_reenrollment_by_code_or_header() {
        let (result, _) = call(response(
            "403 Forbidden",
            &[],
            &error_body("reenrollment_required", "pending"),
        ));
        assert!(matches!(result, Err(ApiError::ReenrollmentRequired { .. })));
        let (result, _) = call(response(
            "403 Forbidden",
            &["Fleet-Enrollment-State: pending", "X-Request-Id: req-2"],
            "",
        ));
        assert_eq!(
            result.unwrap_err(),
            ApiError::ReenrollmentRequired {
                request_id: Some("req-2".into())
            }
        );
        let (result, _) = call(response(
            "403 Forbidden",
            &[],
            &error_body("host_not_active", "no"),
        ));
        assert!(
            matches!(result, Err(ApiError::Forbidden { code, .. }) if code == "host_not_active")
        );
    }

    #[test]
    fn maps_426_with_message() {
        let (result, _) = call(response(
            "426 Upgrade Required",
            &[],
            &error_body(
                "agent_version_unsupported",
                "minimum agent version is 0.2.0",
            ),
        ));
        assert!(matches!(
            result,
            Err(ApiError::AgentVersionUnsupported { message, .. }) if message == "minimum agent version is 0.2.0"
        ));
    }

    #[test]
    fn maps_429_with_retry_after() {
        let (result, _) = call(response(
            "429 Too Many Requests",
            &["Retry-After: 120"],
            &error_body("rate_limited", "slow down"),
        ));
        assert!(matches!(
            result,
            Err(ApiError::RateLimited { retry_after: Some(d), .. }) if d == Duration::from_secs(120)
        ));
    }

    #[test]
    fn maps_413_5xx_and_others_by_status() {
        let (result, _) = call(response("413 Payload Too Large", &[], ""));
        assert!(matches!(result, Err(ApiError::PayloadTooLarge { .. })));
        let (result, _) = call(response(
            "503 Service Unavailable",
            &[],
            "<html>down</html>",
        ));
        assert!(matches!(result, Err(ApiError::Server { status: 503, .. })));
        let (result, _) = call(response(
            "400 Bad Request",
            &[],
            &error_body("validation_failed", "bad field"),
        ));
        assert!(matches!(
            result,
            Err(ApiError::Rejected { status: 400, code, .. }) if code == "validation_failed"
        ));
    }

    #[test]
    fn oversized_or_non_json_success_body_is_rejected() {
        let big = format!("\"{}\"", "a".repeat(MAX_RESPONSE_BYTES as usize + 10));
        let (result, _) = call(response("200 OK", &[], &big));
        assert!(
            matches!(result, Err(ApiError::InvalidResponse(_))),
            "{result:?}"
        );
        let (result, _) = call(response("200 OK", &[], "not json"));
        assert!(matches!(result, Err(ApiError::InvalidResponse(_))));
    }

    #[test]
    fn redirects_are_not_followed() {
        let (result, _) = call(response(
            "307 Temporary Redirect",
            &["Location: https://elsewhere.example.lan/api/v1/heartbeat"],
            "",
        ));
        assert!(
            matches!(result, Err(ApiError::Rejected { status: 307, .. })),
            "{result:?}"
        );
    }

    #[test]
    fn unreachable_server_is_a_transport_error() {
        // Bind then drop a listener, so nothing is listening on the port.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let dir = TempDir::new();
        let pki = TestPki::generate();
        let ca = dir.write("ca.pem", &pki.ca_pem);
        let text = format!(
            "server_url = \"https://localhost:{port}\"\ncredential = \"{}\"\nca_file = \"{}\"\n",
            cfg::CREDENTIAL,
            ca.display()
        );
        let client =
            Client::with_system_bundle(&Config::from_toml(&text).unwrap(), &dir.path("x")).unwrap();
        let result = client.post_json("/api/v1/heartbeat", &serde_json::json!({}));
        assert!(matches!(result, Err(ApiError::Transport(_))), "{result:?}");
    }

    #[test]
    fn client_debug_hides_the_credential() {
        let config = Config::from_toml(&cfg::minimal()).unwrap();
        let dir = TempDir::new();
        let pki = TestPki::generate();
        let ca = dir.write("ca.pem", &pki.ca_pem);
        let config = Config {
            ca_file: Some(ca),
            ..config
        };
        let client = Client::with_system_bundle(&config, &dir.path("x")).unwrap();
        assert!(!format!("{client:?}").contains(cfg::SECRET));
    }

    #[test]
    fn certificate_error_detection() {
        assert!(is_certificate_error(
            "invalid peer certificate: UnknownIssuer"
        ));
        assert!(!is_certificate_error("connection refused"));
    }
}
