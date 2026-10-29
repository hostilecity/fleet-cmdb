//! Agent configuration (FR-1.6, P1-A01).
//!
//! Loads the TOML config file (root-owned, mode `0600`, DEC-03): server URL, credential, heartbeat and
//! inventory intervals with their bounds, log level, an optional path to an extra certificate
//! authority bundle, and the state directory. There is deliberately no setting to disable
//! certificate verification, and unknown keys (such as `insecure`) are rejected.
//!
//! ```toml
//! server_url = "https://fleet-agent.example.lan"
//! credential = "EXAMPLEkey01.EXAMPLE-secret-not-a-real-credential-0001"
//! log_level = "info"                         # optional: error, warn, info, debug, trace
//! # ca_file = "/etc/fleet-agent/ca.pem"      # optional: extra CA bundle for a private CA
//! # state_dir = "/var/lib/fleet-agent"       # optional
//!
//! [heartbeat]                                # optional; seconds
//! interval_seconds = 60
//! min_seconds = 30
//! max_seconds = 600
//!
//! [inventory]                                # optional; seconds
//! interval_seconds = 900
//! min_seconds = 300
//! max_seconds = 21600
//! ```

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

/// Where `fleet-agent install` writes the config (P1-PACKAGING).
pub const DEFAULT_CONFIG_PATH: &str = "/etc/fleet-agent/config.toml";

/// Default state directory (DEC-03).
pub const DEFAULT_STATE_DIR: &str = "/var/lib/fleet-agent";

/// Hard limits and defaults for one reporting interval, in seconds.
struct IntervalLimits {
    name: &'static str,
    /// No configured value, and no server-directed value, may be outside `floor..=ceiling`.
    floor: u64,
    ceiling: u64,
    default_interval: u64,
    default_min: u64,
    default_max: u64,
}

/// FR-1.2: heartbeat every 60 seconds by default.
const HEARTBEAT_LIMITS: IntervalLimits = IntervalLimits {
    name: "heartbeat",
    floor: 10,
    ceiling: 3_600,
    default_interval: 60,
    default_min: 30,
    default_max: 600,
};

/// FR-1.3: inventory every 15 minutes by default.
const INVENTORY_LIMITS: IntervalLimits = IntervalLimits {
    name: "inventory",
    floor: 60,
    ceiling: 86_400,
    default_interval: 900,
    default_min: 300,
    default_max: 21_600,
};

/// The per-host agent credential, `<key_id>.<secret>` (DEC-08).
///
/// `Debug` and `Display` print a placeholder, so the secret cannot reach a log line or error message
/// by accident (NFR-1). Only [`Credential::expose_secret`] returns it, for the `Authorization` header.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct Credential(String);

impl Credential {
    /// Wraps a credential string. Format checks happen in [`Config::from_toml`].
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The full credential. Use only to build the `Authorization` header; never log it.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// The non-secret identifier before the `.`, safe to log for tracing a host (NFR-4).
    pub fn key_id(&self) -> &str {
        self.0.split_once('.').map_or("", |(id, _)| id)
    }

    /// Matches the `credential` pattern in `docs/api/schemas/v1/enroll.response.schema.json`:
    /// `^[A-Za-z0-9_-]{8,64}\.[A-Za-z0-9_-]{32,128}$`.
    fn is_well_formed(&self) -> bool {
        let token_char = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
        match self.0.split_once('.') {
            Some((id, secret)) => {
                (8..=64).contains(&id.len())
                    && (32..=128).contains(&secret.len())
                    && id.chars().all(token_char)
                    && secret.chars().all(token_char)
            }
            None => false,
        }
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credential(<redacted>)")
    }
}

impl fmt::Display for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Log verbosity from the config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "error" => Some(Self::Error),
            "warn" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            "trace" => Some(Self::Trace),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

/// One reporting interval: the starting value and the bounds within which a server-directed value is
/// applied (ADR 0019, P1-AGENT-REPORT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interval {
    pub start: Duration,
    pub min: Duration,
    pub max: Duration,
}

impl Interval {
    /// The interval to use when the server asks for `server_seconds`: clamped to this interval's
    /// configured bounds, so the server can shed load without an agent release but can never push
    /// the agent outside what the operator allowed.
    pub fn clamp_server_value(&self, server_seconds: u64) -> Duration {
        Duration::from_secs(server_seconds).clamp(self.min, self.max)
    }
}

/// A validated configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// The agent API origin, `https://host[:port]`, with no trailing slash. The client adds `/api/v1`.
    pub server_url: String,
    pub credential: Credential,
    pub log_level: LogLevel,
    pub ca_file: Option<PathBuf>,
    pub state_dir: PathBuf,
    pub heartbeat: Interval,
    pub inventory: Interval,
}

/// Why a config could not be loaded. Every message says what to change.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    NotFound(PathBuf),
    Unreadable(PathBuf, String),
    /// Readable or writable by group or others (DEC-03).
    Permissions(PathBuf, u32),
    NotAFile(PathBuf),
    /// TOML syntax error, unknown key, or wrong type.
    Parse(String),
    /// A value is present but not acceptable.
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(path) => write!(
                f,
                "config file {} not found; install the agent with `fleet-agent install`, or pass --config PATH",
                path.display()
            ),
            Self::Unreadable(path, reason) => write!(
                f,
                "cannot read config file {}: {reason} (the agent runs as root; run this command as root)",
                path.display()
            ),
            Self::Permissions(path, mode) => write!(
                f,
                "config file {} has mode {mode:04o}, which lets group or others access the agent credential; fix it with `chmod 600 {}`",
                path.display(),
                path.display()
            ),
            Self::NotAFile(path) => {
                write!(f, "config path {} is not a regular file", path.display())
            }
            Self::Parse(message) => write!(f, "config file is not valid: {message}"),
            Self::Invalid(message) => write!(f, "config file is not valid: {message}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    server_url: Option<String>,
    credential: Option<Credential>,
    log_level: Option<String>,
    ca_file: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    heartbeat: Option<RawInterval>,
    inventory: Option<RawInterval>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInterval {
    interval_seconds: Option<u64>,
    min_seconds: Option<u64>,
    max_seconds: Option<u64>,
}

impl Config {
    /// Reads, permission-checks, and validates the config file at `path`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let metadata = fs::metadata(path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => ConfigError::NotFound(path.to_owned()),
            _ => ConfigError::Unreadable(path.to_owned(), e.to_string()),
        })?;
        if !metadata.is_file() {
            return Err(ConfigError::NotAFile(path.to_owned()));
        }
        check_mode(path, metadata.permissions().mode())?;
        let text = fs::read_to_string(path)
            .map_err(|e| ConfigError::Unreadable(path.to_owned(), e.to_string()))?;
        Self::from_toml(&text)
    }

    /// Parses and validates config text. Error messages never contain the credential.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(text).map_err(|e| parse_error(text, &e))?;

        let server_url = validate_server_url(raw.server_url.as_deref())?;

        let credential = raw.credential.ok_or_else(|| {
            ConfigError::Invalid(
                "missing `credential`; `fleet-agent install` writes it when the host is enrolled"
                    .into(),
            )
        })?;
        if !credential.is_well_formed() {
            return Err(ConfigError::Invalid(
                "`credential` is not a valid agent credential (expected `<key_id>.<secret>` as issued at enrollment); re-enrol with `fleet-agent install --reenroll`"
                    .into(),
            ));
        }

        let log_level = match raw.log_level.as_deref() {
            None => LogLevel::Info,
            Some(value) => LogLevel::parse(value).ok_or_else(|| {
                ConfigError::Invalid(
                    "`log_level` must be one of error, warn, info, debug, trace".into(),
                )
            })?,
        };

        if let Some(ca_file) = &raw.ca_file
            && !ca_file.is_absolute()
        {
            return Err(ConfigError::Invalid(format!(
                "`ca_file` must be an absolute path, got {}",
                ca_file.display()
            )));
        }

        let state_dir = raw
            .state_dir
            .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
        if !state_dir.is_absolute() {
            return Err(ConfigError::Invalid(format!(
                "`state_dir` must be an absolute path, got {}",
                state_dir.display()
            )));
        }

        Ok(Self {
            server_url,
            credential,
            log_level,
            ca_file: raw.ca_file,
            state_dir,
            heartbeat: validate_interval(&HEARTBEAT_LIMITS, raw.heartbeat.unwrap_or_default())?,
            inventory: validate_interval(&INVENTORY_LIMITS, raw.inventory.unwrap_or_default())?,
        })
    }
}

/// DEC-03: the config holds the credential, so only its owner may read or write it.
fn check_mode(path: &Path, mode: u32) -> Result<(), ConfigError> {
    if mode & 0o077 != 0 {
        return Err(ConfigError::Permissions(path.to_owned(), mode & 0o7777));
    }
    Ok(())
}

/// Builds a parse error from the TOML message and position only. The TOML crate's full `Display`
/// quotes the offending source line, which could be the credential line, so it is never used.
fn parse_error(text: &str, error: &toml::de::Error) -> ConfigError {
    let location = error.span().map(|span| {
        let before = &text[..span.start.min(text.len())];
        let line = before.matches('\n').count() + 1;
        let column = before.len() - before.rfind('\n').map_or(0, |i| i + 1) + 1;
        format!("line {line}, column {column}: ")
    });
    let message = error.message().trim_end().replace('\n', " ");
    ConfigError::Parse(format!(
        "{}{}",
        location.unwrap_or_default(),
        redact_credential_text(text, &message)
    ))
}

/// Removes anything that looks like the configured credential value from `message`, as a second
/// guard for messages that echo a value (for example a credential pasted under the wrong key).
fn redact_credential_text(text: &str, message: &str) -> String {
    let mut message = message.to_owned();
    for line in text.lines() {
        let Some((_, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
        if value.contains('.') && value.len() >= 41 && message.contains(value) {
            message = message.replace(value, "<redacted>");
        }
    }
    message
}

fn validate_server_url(value: Option<&str>) -> Result<String, ConfigError> {
    let example = "for example server_url = \"https://fleet-agent.example.lan\"";
    let url = value.ok_or_else(|| {
        ConfigError::Invalid(format!(
            "missing `server_url`; set it to the agent API hostname, {example}"
        ))
    })?;
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("http://") {
        return Err(ConfigError::Invalid(format!(
            "`server_url` must use https; plain http is not allowed because the credential and inventory would travel unencrypted (NFR-1), {example}"
        )));
    }
    let Some(rest) = lower
        .strip_prefix("https://")
        .map(|_| &url["https://".len()..])
    else {
        return Err(ConfigError::Invalid(format!(
            "`server_url` must start with https://, {example}"
        )));
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains('/') {
        return Err(ConfigError::Invalid(format!(
            "`server_url` must be the server address only, without a path (the agent adds /api/v1), {example}"
        )));
    }
    let valid_char =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']');
    if authority.is_empty() || !authority.chars().all(valid_char) {
        return Err(ConfigError::Invalid(format!(
            "`server_url` must be https:// followed by a hostname and optional port, with no user name, query, or spaces, {example}"
        )));
    }
    // Split `host[:port]`, where host may be a bracketed IPv6 literal.
    let (host, port) = match authority.strip_prefix('[') {
        Some(inner) => match inner.split_once(']') {
            Some((v6, after)) if !v6.is_empty() => (
                v6,
                after
                    .strip_prefix(':')
                    .or(if after.is_empty() { None } else { Some("") }),
            ),
            _ => ("", None),
        },
        None => match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    let host_ok = !host.is_empty() && !(authority.starts_with('[') ^ host.contains(':'));
    let port_ok = port.is_none_or(|p| p.parse::<u16>().is_ok_and(|p| p != 0));
    if !host_ok || !port_ok || host.contains(['[', ']']) {
        return Err(ConfigError::Invalid(format!(
            "`server_url` has an invalid hostname or port, {example}"
        )));
    }
    Ok(format!("https://{authority}"))
}

fn validate_interval(limits: &IntervalLimits, raw: RawInterval) -> Result<Interval, ConfigError> {
    let name = limits.name;
    let start = raw.interval_seconds.unwrap_or(limits.default_interval);
    let min = raw.min_seconds.unwrap_or(limits.default_min.min(start));
    let max = raw.max_seconds.unwrap_or(limits.default_max.max(start));
    for (key, value) in [
        ("interval_seconds", start),
        ("min_seconds", min),
        ("max_seconds", max),
    ] {
        if !(limits.floor..=limits.ceiling).contains(&value) {
            return Err(ConfigError::Invalid(format!(
                "`{name}.{key}` is {value}; it must be between {} and {} seconds",
                limits.floor, limits.ceiling
            )));
        }
    }
    if !(min <= start && start <= max) {
        return Err(ConfigError::Invalid(format!(
            "`{name}` needs min_seconds <= interval_seconds <= max_seconds, got {min} <= {start} <= {max}"
        )));
    }
    Ok(Interval {
        start: Duration::from_secs(start),
        min: Duration::from_secs(min),
        max: Duration::from_secs(max),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const SECRET: &str = "EXAMPLE-secret-not-a-real-credential-0001";
    pub const CREDENTIAL: &str = "EXAMPLEkey01.EXAMPLE-secret-not-a-real-credential-0001";

    pub fn minimal() -> String {
        format!("server_url = \"https://fleet-agent.example.lan\"\ncredential = \"{CREDENTIAL}\"\n")
    }

    fn invalid(text: &str) -> String {
        match Config::from_toml(text) {
            Ok(config) => panic!("accepted invalid config: {config:?}"),
            Err(e) => {
                let message = e.to_string();
                assert!(
                    !message.contains(SECRET),
                    "error leaks the credential: {message}"
                );
                message
            }
        }
    }

    #[test]
    fn minimal_config_gets_defaults() {
        let config = Config::from_toml(&minimal()).unwrap();
        assert_eq!(config.server_url, "https://fleet-agent.example.lan");
        assert_eq!(config.credential.expose_secret(), CREDENTIAL);
        assert_eq!(config.credential.key_id(), "EXAMPLEkey01");
        assert_eq!(config.log_level, LogLevel::Info);
        assert_eq!(config.ca_file, None);
        assert_eq!(config.state_dir, PathBuf::from(DEFAULT_STATE_DIR));
        assert_eq!(config.heartbeat.start, Duration::from_secs(60));
        assert_eq!(config.heartbeat.min, Duration::from_secs(30));
        assert_eq!(config.heartbeat.max, Duration::from_secs(600));
        assert_eq!(config.inventory.start, Duration::from_secs(900));
    }

    #[test]
    fn full_config_is_read() {
        let text = format!(
            "{}log_level = \"debug\"\nca_file = \"/etc/fleet-agent/ca.pem\"\nstate_dir = \"/srv/fleet-agent\"\n\
             [heartbeat]\ninterval_seconds = 120\nmin_seconds = 60\nmax_seconds = 300\n\
             [inventory]\ninterval_seconds = 1800\n",
            minimal()
        );
        let config = Config::from_toml(&text).unwrap();
        assert_eq!(config.log_level, LogLevel::Debug);
        assert_eq!(
            config.ca_file,
            Some(PathBuf::from("/etc/fleet-agent/ca.pem"))
        );
        assert_eq!(config.state_dir, PathBuf::from("/srv/fleet-agent"));
        assert_eq!(
            config.heartbeat,
            Interval {
                start: Duration::from_secs(120),
                min: Duration::from_secs(60),
                max: Duration::from_secs(300)
            }
        );
        assert_eq!(config.inventory.start, Duration::from_secs(1800));
    }

    #[test]
    fn http_server_url_is_rejected() {
        for url in [
            "http://fleet-agent.example.lan",
            "HTTP://fleet-agent.example.lan:8080",
        ] {
            let text = format!("server_url = \"{url}\"\ncredential = \"{CREDENTIAL}\"\n");
            assert!(invalid(&text).contains("must use https"), "{url}");
        }
    }

    #[test]
    fn other_bad_server_urls_are_rejected() {
        for url in [
            "fleet-agent.example.lan",
            "ftp://fleet-agent.example.lan",
            "https://",
            "https://fleet-agent.example.lan/api/v1",
            "https://user@fleet-agent.example.lan",
            "https://fleet-agent.example.lan?x=1",
            "https://fleet-agent.example.lan:0",
            "https://fleet-agent.example.lan:99999",
            "https://fleet agent.example.lan",
        ] {
            let text = format!("server_url = \"{url}\"\ncredential = \"{CREDENTIAL}\"\n");
            invalid(&text);
        }
    }

    #[test]
    fn good_server_urls_are_normalised() {
        for (url, expected) in [
            (
                "https://fleet-agent.example.lan/",
                "https://fleet-agent.example.lan",
            ),
            (
                "https://fleet-agent.example.lan:8443",
                "https://fleet-agent.example.lan:8443",
            ),
            ("https://192.0.2.10", "https://192.0.2.10"),
            ("https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
        ] {
            let text = format!("server_url = \"{url}\"\ncredential = \"{CREDENTIAL}\"\n");
            assert_eq!(Config::from_toml(&text).unwrap().server_url, expected);
        }
    }

    #[test]
    fn insecure_key_is_rejected_as_unknown() {
        let message = invalid(&format!("{}insecure = true\n", minimal()));
        assert!(message.contains("unknown field `insecure`"), "{message}");
        let message = invalid(&format!("{}[heartbeat]\ninsecure = true\n", minimal()));
        assert!(message.contains("unknown field `insecure`"), "{message}");
    }

    #[test]
    fn missing_keys_say_what_to_set() {
        assert!(invalid("credential = \"x\"\n").contains("missing `server_url`"));
        assert!(
            invalid("server_url = \"https://fleet-agent.example.lan\"\n")
                .contains("missing `credential`")
        );
    }

    #[test]
    fn malformed_credential_is_rejected_without_echoing_it() {
        for bad in [
            "EXAMPLE-secret-not-a-real-credential-0001",
            "EXAMPLEkey01.short",
            "EXAMPLEkey01.EXAMPLE secret not a real credential 0001",
        ] {
            let text = format!(
                "server_url = \"https://fleet-agent.example.lan\"\ncredential = \"{bad}\"\n"
            );
            let message = invalid(&text);
            assert!(message.contains("`credential` is not a valid"), "{message}");
            assert!(!message.contains(bad));
        }
    }

    #[test]
    fn syntax_errors_give_a_position_and_never_the_credential() {
        let text = format!(
            "server_url = \"https://fleet-agent.example.lan\"\ncredential = \"{CREDENTIAL}\n"
        );
        let message = invalid(&text);
        assert!(message.contains("line 2"), "{message}");

        // A credential pasted under a key with the wrong type.
        let text = format!(
            "{}[heartbeat]\ninterval_seconds = \"{CREDENTIAL}\"\n",
            minimal()
        );
        let message = invalid(&text);
        assert!(message.contains("line 4"), "{message}");
    }

    #[test]
    fn bad_log_level_and_relative_paths_are_rejected() {
        assert!(invalid(&format!("{}log_level = \"loud\"\n", minimal())).contains("log_level"));
        assert!(invalid(&format!("{}ca_file = \"ca.pem\"\n", minimal())).contains("ca_file"));
        assert!(invalid(&format!("{}state_dir = \"state\"\n", minimal())).contains("state_dir"));
    }

    #[test]
    fn intervals_outside_bounds_are_rejected() {
        let message = invalid(&format!("{}[heartbeat]\ninterval_seconds = 1\n", minimal()));
        assert!(message.contains("between 10 and 3600"), "{message}");
        invalid(&format!(
            "{}[inventory]\ninterval_seconds = 100000\n",
            minimal()
        ));
        let message = invalid(&format!(
            "{}[heartbeat]\ninterval_seconds = 60\nmin_seconds = 120\n",
            minimal()
        ));
        assert!(
            message.contains("min_seconds <= interval_seconds"),
            "{message}"
        );
        invalid(&format!(
            "{}[heartbeat]\ninterval_seconds = -5\n",
            minimal()
        ));
    }

    #[test]
    fn default_bounds_widen_to_include_a_configured_interval() {
        let config = Config::from_toml(&format!(
            "{}[heartbeat]\ninterval_seconds = 15\n",
            minimal()
        ))
        .unwrap();
        assert_eq!(config.heartbeat.min, Duration::from_secs(15));
        let config = Config::from_toml(&format!(
            "{}[heartbeat]\ninterval_seconds = 1200\n",
            minimal()
        ))
        .unwrap();
        assert_eq!(config.heartbeat.max, Duration::from_secs(1200));
    }

    #[test]
    fn server_directed_intervals_are_clamped_to_config_bounds() {
        let config = Config::from_toml(&minimal()).unwrap();
        let hb = config.heartbeat;
        assert_eq!(hb.clamp_server_value(120), Duration::from_secs(120));
        assert_eq!(hb.clamp_server_value(1), Duration::from_secs(30));
        assert_eq!(hb.clamp_server_value(0), Duration::from_secs(30));
        assert_eq!(hb.clamp_server_value(u64::MAX), Duration::from_secs(600));
        assert_eq!(
            config.inventory.clamp_server_value(60),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn credential_never_appears_in_debug_or_display() {
        let config = Config::from_toml(&minimal()).unwrap();
        for text in [
            format!("{config:?}"),
            format!("{config:#?}"),
            format!("{:?}", config.credential),
            format!("{}", config.credential),
        ] {
            assert!(!text.contains(SECRET), "leaked: {text}");
            assert!(!text.contains(CREDENTIAL));
        }
        assert!(format!("{config:?}").contains("Credential(<redacted>)"));
    }

    #[test]
    fn group_or_world_access_is_refused() {
        let path = Path::new("/etc/fleet-agent/config.toml");
        assert!(check_mode(path, 0o100600).is_ok());
        assert!(check_mode(path, 0o100400).is_ok());
        for mode in [0o100640, 0o100604, 0o100644, 0o100660, 0o100602] {
            let error = check_mode(path, mode).unwrap_err();
            assert!(error.to_string().contains("chmod 600"), "{error}");
        }
    }
}
