//! Firewall (P2-A03): `firewall.backend` and `firewall.enabled`.
//!
//! The mechanism and whether it is on come from systemd and one configuration file, not from asking
//! the firewall: `ufw status`, `firewall-cmd --state`, `nft list ruleset`, and `iptables -S` all need
//! `CAP_NET_ADMIN`, which the agent's unit does not have (`CapabilityBoundingSet=CAP_DAC_READ_SEARCH`,
//! see `agent/contrib/README.md`), and widening the sandbox for one fact is not worth it. The one
//! command used is `systemctl show` for four units, read-only and with fixed arguments
//! ([`super::systemd`]).
//!
//! | Backend | Present when | Enabled when |
//! |---|---|---|
//! | `ufw` | `ufw.service` exists | the unit is active and starts at boot, and `/etc/ufw/ufw.conf` has `ENABLED=yes` |
//! | `firewalld` | `firewalld.service` exists | the unit is active and starts at boot |
//! | `nftables` | `nftables.service` exists | the unit is active and starts at boot |
//! | `iptables` | `iptables` is installed (`/usr/sbin/iptables`) or `netfilter-persistent.service` exists | `netfilter-persistent.service` is active and starts at boot |
//! | `none` | none of the above | not enabled |
//!
//! The backend is the first of `ufw`, `firewalld`, `nftables`, `iptables` that is present *and*
//! enabled; if none is enabled, the first that is present; if none is present, `none`. So a host with
//! `ufw` installed but off and `nftables` loading a ruleset at boot reports `nftables`, enabled.
//!
//! What this cannot see: rules loaded by hand or by a script that is not one of these units, and
//! whether an enabled `nftables` or `netfilter-persistent` ruleset is empty. "Enabled" means the
//! mechanism is set up to load its rules at boot and has done so. If `systemctl` cannot be read,
//! both facts are `unreadable` with the reason.

use std::collections::HashMap;

use serde_json::json;

use super::manifest::FactType;
use super::systemd::{self, UnitInfo};
use super::{Ctx, Outcome, io_reason};

const UFW_CONF: &str = "/etc/ufw/ufw.conf";
const IPTABLES: &[&str] = &["/usr/sbin/iptables", "/sbin/iptables"];

pub const KEYS: &[(&str, FactType)] = &[
    ("firewall.backend", FactType::String),
    ("firewall.enabled", FactType::Boolean),
];

/// What the host has, as far as it can be seen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Probe {
    pub ufw: Option<UnitInfo>,
    /// `ENABLED=yes` in `/etc/ufw/ufw.conf`.
    pub ufw_conf_enabled: bool,
    pub firewalld: Option<UnitInfo>,
    pub nftables: Option<UnitInfo>,
    pub persistent: Option<UnitInfo>,
    pub iptables_installed: bool,
}

pub fn read(ctx: &Ctx) -> HashMap<&'static str, Outcome> {
    let fail = |reason: String| -> HashMap<&'static str, Outcome> {
        KEYS.iter()
            .map(|(key, _)| (*key, Outcome::Unreadable(reason.clone())))
            .collect()
    };
    let units = [
        "ufw.service",
        "firewalld.service",
        "nftables.service",
        "netfilter-persistent.service",
    ];
    let states = match systemd::show(ctx, &units) {
        Ok(states) => states,
        Err(reason) => return fail(reason),
    };
    let mut states = states.into_iter();
    let (ufw, firewalld, nftables, persistent) = (
        states.next().flatten(),
        states.next().flatten(),
        states.next().flatten(),
        states.next().flatten(),
    );
    let ufw_conf_enabled = if ufw.is_some() {
        match ctx.read(UFW_CONF, 64 * 1024) {
            Ok(bytes) => ufw_conf_enabled(&bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return fail(io_reason(UFW_CONF, &e)),
        }
    } else {
        false
    };
    let mut iptables_installed = false;
    for path in IPTABLES {
        match ctx.stat(path) {
            Ok(_) => {
                iptables_installed = true;
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return fail(io_reason(path, &e)),
        }
    }
    facts(&Probe {
        ufw,
        ufw_conf_enabled,
        firewalld,
        nftables,
        persistent,
        iptables_installed,
    })
}

/// Whether a `ufw.conf` says `ENABLED=yes` (case-insensitive, last assignment wins).
pub fn ufw_conf_enabled(bytes: &[u8]) -> bool {
    let mut enabled = false;
    for line in String::from_utf8_lossy(bytes).lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ENABLED")
            && let Some(value) = rest.trim_start().strip_prefix('=')
        {
            enabled = value
                .trim()
                .trim_matches(['"', '\''])
                .eq_ignore_ascii_case("yes");
        }
    }
    enabled
}

/// The two facts for a probe of the host.
pub fn facts(probe: &Probe) -> HashMap<&'static str, Outcome> {
    let up = |unit: &Option<UnitInfo>| {
        unit.as_ref()
            .is_some_and(|u| u.is_active() && u.starts_at_boot())
    };
    // (name, present, enabled), in the order of preference.
    let candidates = [
        (
            "ufw",
            probe.ufw.is_some(),
            up(&probe.ufw) && probe.ufw_conf_enabled,
        ),
        ("firewalld", probe.firewalld.is_some(), up(&probe.firewalld)),
        ("nftables", probe.nftables.is_some(), up(&probe.nftables)),
        (
            "iptables",
            probe.iptables_installed || probe.persistent.is_some(),
            up(&probe.persistent),
        ),
    ];
    let chosen = candidates
        .iter()
        .find(|(_, present, enabled)| *present && *enabled)
        .or_else(|| candidates.iter().find(|(_, present, _)| *present));
    let (backend, enabled) = match chosen {
        Some((name, _, enabled)) => (*name, *enabled),
        None => ("none", false),
    };
    HashMap::from([
        ("firewall.backend", Outcome::Ok(json!(backend))),
        ("firewall.enabled", Outcome::Ok(json!(enabled))),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(active: &str, enabled: &str) -> Option<UnitInfo> {
        Some(UnitInfo {
            active: active.into(),
            enabled: enabled.into(),
        })
    }

    fn result(probe: &Probe) -> (String, bool) {
        let facts = facts(probe);
        let backend = match &facts["firewall.backend"] {
            Outcome::Ok(v) => v.as_str().unwrap().to_owned(),
            other => panic!("{other:?}"),
        };
        let enabled = match &facts["firewall.enabled"] {
            Outcome::Ok(v) => v.as_bool().unwrap(),
            other => panic!("{other:?}"),
        };
        (backend, enabled)
    }

    #[test]
    fn nothing_installed_is_none_and_not_enabled() {
        assert_eq!(result(&Probe::default()), ("none".into(), false));
    }

    #[test]
    fn ufw_needs_the_unit_and_the_conf_flag() {
        let on = Probe {
            ufw: unit("active", "enabled"),
            ufw_conf_enabled: true,
            ..Probe::default()
        };
        assert_eq!(result(&on), ("ufw".into(), true));
        let flag_off = Probe {
            ufw_conf_enabled: false,
            ..on.clone()
        };
        assert_eq!(result(&flag_off), ("ufw".into(), false));
        let stopped = Probe {
            ufw: unit("inactive", "enabled"),
            ..on.clone()
        };
        assert_eq!(result(&stopped), ("ufw".into(), false));
        let not_at_boot = Probe {
            ufw: unit("active", "disabled"),
            ..on
        };
        assert_eq!(result(&not_at_boot), ("ufw".into(), false));
    }

    #[test]
    fn an_enabled_mechanism_beats_a_disabled_one() {
        let probe = Probe {
            ufw: unit("inactive", "disabled"),
            nftables: unit("active", "enabled"),
            ..Probe::default()
        };
        assert_eq!(result(&probe), ("nftables".into(), true));
        let both = Probe {
            ufw: unit("active", "enabled"),
            ufw_conf_enabled: true,
            firewalld: unit("active", "enabled"),
            nftables: unit("active", "enabled"),
            ..Probe::default()
        };
        assert_eq!(
            result(&both),
            ("ufw".into(), true),
            "ufw is first in the order"
        );
    }

    #[test]
    fn the_first_present_mechanism_is_the_backend_when_none_is_enabled() {
        let probe = Probe {
            firewalld: unit("inactive", "disabled"),
            nftables: unit("inactive", "disabled"),
            ..Probe::default()
        };
        assert_eq!(result(&probe), ("firewalld".into(), false));
    }

    #[test]
    fn plain_iptables_is_enabled_only_through_netfilter_persistent() {
        let installed = Probe {
            iptables_installed: true,
            ..Probe::default()
        };
        assert_eq!(result(&installed), ("iptables".into(), false));
        let persistent = Probe {
            iptables_installed: true,
            persistent: unit("active", "enabled"),
            ..Probe::default()
        };
        assert_eq!(result(&persistent), ("iptables".into(), true));
    }

    #[test]
    fn ufw_conf_parsing() {
        assert!(ufw_conf_enabled(b"# comment\nENABLED=yes\nLOGLEVEL=low\n"));
        assert!(ufw_conf_enabled(b"ENABLED = YES\n"));
        assert!(!ufw_conf_enabled(b"ENABLED=no\n"));
        assert!(!ufw_conf_enabled(b"# ENABLED=yes\n"));
        assert!(
            !ufw_conf_enabled(b"ENABLED=yes\nENABLED=no\n"),
            "the last wins"
        );
        assert!(!ufw_conf_enabled(b""));
        assert!(!ufw_conf_enabled(b"\xff\xfe"));
    }
}
