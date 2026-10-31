//! Step 1 of `install`: checks that change nothing (P1-A10). Each failure says what is wrong and the
//! next step, and exits 3 (`Failure::Preflight`), or 2 for a usage problem.

use std::fs;
use std::path::{Path, PathBuf};

use crate::client::{ApiError, Client, is_certificate_error, trust_roots};
use crate::config::{Config, ConfigError};

use super::fsx::{self, Kind};
use super::systemd::UNIT_MARKER;
use super::token::TokenSource;
use super::ui::Ui;
use super::{Failure, Host, InstallError, InstallOptions};

/// What the checks decided.
pub struct Plan {
    pub server_url: String,
    /// `--ca-file`, to copy to `/etc/fleet-agent/ca.pem`.
    pub ca_source: Option<PathBuf>,
    /// The CA bundle to trust for this run: `--ca-file`, or the existing config's `ca_file`.
    pub ca_for_run: Option<PathBuf>,
    /// The current, valid config, if the VM is enrolled.
    pub existing: Option<Config>,
    /// Enroll anew (onboarding or token) rather than keep the existing credential.
    pub enroll_anew: bool,
    pub token_source: Option<TokenSource>,
}

fn fail(what: impl Into<String>, next: impl Into<String>) -> InstallError {
    InstallError::new(Failure::Preflight, what, next)
}

pub fn check(host: &Host, options: &InstallOptions, ui: &mut Ui) -> Result<Plan, InstallError> {
    if !host.is_root {
        return Err(fail(
            "install must run as root: it installs a system service and writes its root-only config (DEC-03)",
            format!("Run it again with sudo: {}", host.sudo_command),
        ));
    }
    let os = check_os(host)?;
    if let Some(reason) = host.systemd.unavailable() {
        return Err(fail(
            format!("{reason}; the agent runs as a systemd service"),
            "Install on a Debian 13 VM booted with systemd (not in a container without systemd).",
        ));
    }
    ui.detail(&format!(
        "This VM: {os}, {}, systemd, running as root.",
        host.machine
    ));

    check_paths(host)?;
    let existing = existing_config(host, options)?;
    let enroll_anew = existing.is_none() || options.reenroll || options.token.is_some();

    let server_url = match (&options.server, &existing) {
        (Some(given), _) => crate::config::validate_server_url(Some(given)).map_err(|e| {
            InstallError::new(
                Failure::Usage,
                format!("--server is not valid: {}", e.to_string().trim_start_matches("config file is not valid: ")),
                "Pass the agent API address shown on the dashboard's install page, for example --server https://agent.example.lan",
            )
        })?,
        (None, Some(config)) => config.server_url.clone(),
        (None, None) => {
            return Err(InstallError::new(
                Failure::Usage,
                "--server is required for a first install",
                "Pass the agent API address shown on the dashboard's install page, for example: sudo fleet-agent install --server https://agent.example.lan",
            ));
        }
    };
    if let Some(config) = &existing
        && config.server_url != server_url
    {
        if !enroll_anew {
            return Err(fail(
                format!(
                    "this VM is already enrolled with {}, not {server_url}; its credential works only with the server that issued it",
                    config.server_url
                ),
                format!(
                    "To keep the current enrollment, run the command without --server. To move this VM to {server_url}, add --reenroll (or use --token with a one-time token from that server)."
                ),
            ));
        }
        ui.detail(&format!(
            "Moving this VM from {} to {server_url}.",
            config.server_url
        ));
    }

    let ca_source = match &options.ca_file {
        Some(path) => Some(check_ca_file(host, path)?),
        None => None,
    };
    let ca_for_run = ca_source
        .clone()
        .or_else(|| existing.as_ref().and_then(|c| c.ca_file.clone()));
    check_server(host, &server_url, ca_for_run.as_deref())?;
    ui.detail(&format!(
        "Server {server_url}: reachable, certificate trusted, agent API answering."
    ));

    Ok(Plan {
        server_url,
        ca_source,
        ca_for_run,
        existing,
        enroll_anew,
        token_source: options.token,
    })
}

/// Largest `os-release` read; real ones are well under 1 KiB.
const OS_RELEASE_MAX_BYTES: u64 = 64 * 1024;

/// DEC-01: Debian 13 on x86_64. Returns the OS name for the summary.
fn check_os(host: &Host) -> Result<String, InstallError> {
    let next = "fleet-agent supports Debian 13 on x86_64 only (DEC-01). Install it on a Debian 13 x86_64 VM; supporting another system needs a new decision by the fleet owner.";
    // Read like the collectors read it (bounded, regular files only, never waiting on a FIFO) and parsed
    // by the same parser, so preflight and the inventory agree about the system (review of #67).
    let text = host
        .paths
        .os_release()
        .iter()
        .find_map(|p| fsx::read_regular(p, OS_RELEASE_MAX_BYTES, fsx::Symlinks::Follow).ok())
        .ok_or_else(|| {
            fail(
                "cannot read /etc/os-release to identify the operating system",
                next,
            )
        })?;
    let release = crate::collect::parse_os_release(&text).map_err(|e| {
        fail(
            format!("cannot identify the operating system: /etc/os-release {e}"),
            next,
        )
    })?;
    let id = release.id.unwrap_or_default();
    let version = release.version_id.unwrap_or_default();
    let pretty = crate::logging::sanitize(
        &release
            .pretty_name
            .unwrap_or_else(|| format!("{id} {version}")),
        100,
    );
    if id != "debian" || version != "13" {
        return Err(fail(format!("this VM runs {pretty}, not Debian 13"), next));
    }
    if host.machine != "x86_64" {
        return Err(fail(
            format!(
                "this VM's architecture is {}, not x86_64",
                crate::logging::sanitize(&host.machine, 40)
            ),
            next,
        ));
    }
    Ok(pretty)
}

/// Refuses any existing path the installer would write or replace that is not safe to use.
fn check_paths(host: &Host) -> Result<(), InstallError> {
    let paths = &host.paths;
    let uid = host.owner_uid;
    let unsafe_path = |path: &Path, reason: String, fix: &str| {
        fail(
            format!("{} {reason}; the installer will not use it", path.display()),
            format!("{fix} Then run the same command again."),
        )
    };
    let own_dir_fix = "If it is left from an earlier install, remove it with `sudo fleet-agent uninstall` or by hand; otherwise move it out of the way.";
    for dir in [
        paths.lib_dir(),
        paths.versions_dir(),
        paths.versions_dir().join(crate::AGENT_VERSION),
        paths.etc_dir(),
    ] {
        if let Some(reason) = fsx::check_dir(&dir, uid) {
            return Err(unsafe_path(&dir, reason, own_dir_fix));
        }
    }
    for link in [paths.current(), paths.previous(), paths.bin_link()] {
        match fsx::kind(&link)
            .map_err(|e| unsafe_path(&link, format!("cannot be inspected ({e})"), own_dir_fix))?
        {
            Kind::Missing | Kind::Symlink(_) => {}
            _ => {
                return Err(unsafe_path(
                    &link,
                    "exists and is not a symlink the installer made".into(),
                    "Move it out of the way (for example a fleet-agent copied there by hand).",
                ));
            }
        }
    }
    if let Some(reason) = fsx::check_private_dir(&paths.state_dir(), uid) {
        return Err(unsafe_path(
            &paths.state_dir(),
            reason,
            "The agent's state directory must be a real directory owned by root with mode 0700. If it is the agent's own, fix it with `chmod 700` or `chown root:root`; otherwise move it away.",
        ));
    }
    for file in [paths.ca(), paths.unit()] {
        if let Some(reason) = fsx::check_file(&file, uid) {
            return Err(unsafe_path(&file, reason, own_dir_fix));
        }
    }
    if let Ok(text) = fs::read_to_string(paths.unit())
        && !text.starts_with(UNIT_MARKER)
    {
        return Err(unsafe_path(
            &paths.unit(),
            "was not written by fleet-agent install".into(),
            "Move it away (keep local changes in a drop-in made with `systemctl edit fleet-agent`).",
        ));
    }
    Ok(())
}

/// The existing config, if any. An unsafe one (wrong owner or mode) is always refused; an invalid one
/// only when the credential would be kept.
fn existing_config(host: &Host, options: &InstallOptions) -> Result<Option<Config>, InstallError> {
    let path = host.paths.config();
    let anew = options.reenroll || options.token.is_some();
    match Config::load_as(&path, host.owner_uid) {
        Ok(config) => Ok(Some(config)),
        Err(ConfigError::NotFound(_)) => Ok(None),
        // Enrolling anew replaces it.
        Err(ConfigError::Parse(_) | ConfigError::Invalid(_)) if anew => Ok(None),
        Err(error @ (ConfigError::Parse(_) | ConfigError::Invalid(_))) => Err(fail(
            format!(
                "the existing {} is not valid: {}",
                path.display(),
                error
                    .to_string()
                    .trim_start_matches("config file is not valid: ")
            ),
            "Fix it (check with `sudo fleet-agent check-config`), or enroll again and replace it with --reenroll or --token.",
        )),
        Err(error) => Err(fail(
            format!("the existing config is not safe to use: {error}"),
            "Fix the file as described, or remove it to enroll this VM again. Then run the same command again.",
        )),
    }
}

/// `--ca-file` must be readable and hold only PEM certificates. Returns its absolute path.
fn check_ca_file(host: &Host, path: &Path) -> Result<PathBuf, InstallError> {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_owned());
    if absolute.to_str().is_none() {
        return Err(fail(
            "--ca-file path is not valid UTF-8",
            "Copy the certificate to a plain path such as /root/fleet-ca.pem.",
        ));
    }
    trust_roots(&host.system_ca_bundle, Some(&absolute)).map_err(|e| {
        fail(
            format!("--ca-file cannot be used: {e}"),
            "Pass the PEM file of the certificate authority that signed the server's certificate (-----BEGIN CERTIFICATE-----).",
        )
    })?;
    Ok(absolute)
}

/// The server must answer as the agent API (an unknown `/api/v1` path gets the JSON `not_found`
/// envelope), over TLS that this VM trusts. Creates nothing on the server.
fn check_server(host: &Host, server_url: &str, ca: Option<&Path>) -> Result<(), InstallError> {
    let client = Client::anonymous(server_url, ca, &host.system_ca_bundle).map_err(|e| {
        fail(
            format!("no trusted certificate authorities: {e}"),
            "Install the ca-certificates package, or pass --ca-file for a private certificate authority.",
        )
    })?;
    let request_id = |e: &ApiError| {
        e.request_id()
            .map(|id| format!(" (request id {id})"))
            .unwrap_or_default()
    };
    match client.post_json("/api/v1", &serde_json::json!({})) {
        Err(ApiError::Rejected {
            status: 404, code, ..
        }) if code == "not_found" => Ok(()),
        Err(ApiError::Transport(message)) if is_certificate_error(&message) => Err(fail(
            format!("{server_url} presented a certificate this VM does not trust ({message})"),
            "If the server uses a private certificate authority, add --ca-file /path/to/ca.pem. Otherwise check the address is the agent hostname and this VM's clock is right (`date`).",
        )),
        Err(ApiError::Transport(message)) => Err(fail(
            format!("cannot reach {server_url}: {message}"),
            "Check the address (the agent hostname from the dashboard's install page), DNS, and that this VM can reach the server on that port.",
        )),
        Err(error @ ApiError::Server { status, .. }) => Err(InstallError::new(
            Failure::Server,
            format!(
                "{server_url} answered with a server error ({status}){}",
                request_id(&error)
            ),
            "The server is reachable but failing. Try again in a few minutes; if it persists, check the server logs for the request id.",
        )),
        Err(error @ ApiError::RateLimited { .. }) => Err(InstallError::new(
            Failure::Server,
            format!(
                "{server_url} is limiting requests from this address{}",
                request_id(&error)
            ),
            "Wait a minute, then run the same command again.",
        )),
        other => Err(fail(
            format!(
                "{server_url} answered, but not as the Fleet CMDB agent API (HTTP {})",
                match &other {
                    Ok(response) => response.status,
                    Err(error) => error.status(),
                }
            ),
            "Use the agent hostname from the dashboard's install page, not the dashboard address.",
        )),
    }
}
