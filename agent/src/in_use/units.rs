//! From a socket's cgroup to its systemd service, and from a service to its main executable (VT-A01).
//!
//! - [`unit_of`]: a cgroup path under `/sys/fs/cgroup` names a service only inside `system.slice` (and
//!   the slices below it): `system.slice/ssh.service`, `system.slice/system-getty.slice/getty@tty1.service`.
//!   A sub-cgroup of a service (a service with `Delegate=yes` makes its own) still belongs to the
//!   service. Anything else (a container's `.scope`, `user.slice`, the root) is not a service and its
//!   sockets are counted, not named. `init.scope` is systemd itself: a socket it listens on for socket
//!   activation is matched with `systemctl list-sockets` ([`parse_list_sockets`]).
//! - [`parse_show`]: `systemctl show --property=Id,ExecStart -- UNIT...`, which the agent runs with fixed
//!   arguments and the unit names after `--`; only the executables' paths are kept, never their
//!   arguments.

use std::collections::HashMap;
use std::net::IpAddr;

/// What a socket's cgroup says about who listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    Service(String),
    /// systemd itself (`init.scope`): socket activation.
    Systemd,
    /// Not a systemd service: counted, not named.
    Other,
}

/// The owner of a cgroup, given its path relative to the cgroup root.
pub fn unit_of(path: &str) -> Owner {
    if path == "init.scope" {
        return Owner::Systemd;
    }
    let mut parts = path.split('/');
    if parts.next() != Some("system.slice") {
        return Owner::Other;
    }
    for part in parts {
        if part.ends_with(".service") && service_name(part) {
            return Owner::Service(part.to_owned());
        }
        if !part.ends_with(".slice") {
            return Owner::Other;
        }
    }
    Owner::Other
}

/// Whether a name systemd gave a cgroup or listed is a service name the agent passes to `systemctl
/// show` (after `--`, with no shell): the unit name alphabet plus `\` for systemd's escapes, at most
/// 256 bytes, not a template (`ssh@.service`, which has no executable of its own).
pub fn service_name(name: &str) -> bool {
    (".service".len() + 1..=256).contains(&name.len())
        && name.ends_with(".service")
        && !name.starts_with(['-', '.'])
        && !name.contains("@.")
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'.' | b'_' | b'@' | b'+' | b'-' | b'\\' | b':')
        })
}

/// The executables of each unit in `systemctl show --property=Id,ExecStart` output: one block per
/// unit, blank lines between. `expected` blocks must be there, or the output is not read.
pub fn parse_show(output: &[u8], expected: usize) -> Result<HashMap<String, Vec<String>>, String> {
    let text = std::str::from_utf8(output)
        .map_err(|_| "systemctl show printed something that is not UTF-8")?;
    let mut units = HashMap::new();
    let mut blocks = 0;
    for block in text.split("\n\n") {
        if block.trim().is_empty() {
            continue;
        }
        blocks += 1;
        let mut id = None;
        let mut paths = Vec::new();
        for line in block.lines() {
            if let Some(value) = line.strip_prefix("Id=") {
                id = Some(value.trim().to_owned());
            } else if let Some(value) = line.strip_prefix("ExecStart=") {
                paths.extend(exec_paths(value));
            }
        }
        let id = id.ok_or("systemctl show printed a unit without its Id")?;
        units.insert(id, paths);
    }
    if blocks != expected {
        return Err(format!(
            "systemctl show described {blocks} units when {expected} were asked about"
        ));
    }
    Ok(units)
}

/// The `path=` of each command in an `ExecStart=` value:
/// `{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; ignore_errors=no ; ... }`, one group per command.
fn exec_paths(value: &str) -> Vec<String> {
    value
        .split("path=")
        .skip(1)
        .filter_map(|rest| {
            let path = rest.split(" ;").next().unwrap_or("").trim();
            path.starts_with('/').then(|| path.to_owned())
        })
        .collect()
}

/// One IP socket systemd listens on for a service (`systemctl list-sockets`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activated {
    /// `None` for the wildcard address.
    pub address: Option<IpAddr>,
    pub port: u16,
    pub services: Vec<String>,
}

/// `systemctl list-sockets --full --no-legend --no-pager` output: `LISTEN UNIT ACTIVATES` per line.
/// Lines that are not IP sockets (`/run/...`, netlink, vsock) are skipped; an activated name that is
/// not a service name (a template) is left out, so that socket stays unnamed.
pub fn parse_list_sockets(output: &[u8]) -> Result<Vec<Activated>, String> {
    let text = std::str::from_utf8(output)
        .map_err(|_| "systemctl list-sockets printed something that is not UTF-8")?;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(listen) = fields.next() else {
            continue;
        };
        let _unit = fields.next();
        let services: Vec<String> = fields
            .flat_map(|f| f.split(','))
            .map(str::trim)
            .filter(|name| service_name(name))
            .map(str::to_owned)
            .collect();
        let Some((address, port)) = listen.rsplit_once(':') else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        let address = address.trim_start_matches('[').trim_end_matches(']');
        let address = match address {
            "*" | "" => None,
            other => match other.parse::<IpAddr>() {
                Ok(ip) if ip.is_unspecified() => None,
                Ok(ip) => Some(ip),
                Err(_) => continue,
            },
        };
        out.push(Activated {
            address,
            port,
            services,
        });
    }
    Ok(out)
}
