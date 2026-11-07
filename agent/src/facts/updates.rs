//! Automatic updates (P2-A02): `auto_updates.installed` and `auto_updates.enabled`, for the
//! mechanism of Debian 13, `unattended-upgrades` and its apt timers (DEC-01).
//!
//! - `installed`: `/usr/bin/unattended-upgrade`, the program the package ships, exists.
//! - `enabled`: installed, and all of
//!   - `APT::Periodic::Enable` is not 0 (absent means on), and `APT::Periodic::Update-Package-Lists`
//!     and `APT::Periodic::Unattended-Upgrade` are intervals that run (`always`, or above 0 with an
//!     optional `s`, `m`, `h`, or `d` unit) in apt's effective configuration (`apt-config dump`,
//!     read-only, fixed arguments);
//!   - `apt-daily.timer` and `apt-daily-upgrade.timer` are active and enabled (`UnitFileState=enabled`).
//!
//!   A host without the package is simply not enabled, without running anything else. If a source
//!   cannot be read (`apt-config` or `systemctl` missing or failing), `enabled` is `unreadable` with
//!   the reason; `installed` stays known.
//!
//! The parser of `apt-config dump` is a pure function over its output.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::json;

use super::host::Command;
use super::manifest::FactType;
use super::systemd;
use super::{Ctx, Outcome, io_reason};

const PROGRAM_PATH: &str = "/usr/bin/unattended-upgrade";
const APT_CONFIG: &[&str] = &["/usr/bin/apt-config"];
const TIMERS: [&str; 2] = ["apt-daily.timer", "apt-daily-upgrade.timer"];

pub const KEYS: &[(&str, FactType)] = &[
    ("auto_updates.installed", FactType::Boolean),
    ("auto_updates.enabled", FactType::Boolean),
];

pub fn read(ctx: &Ctx) -> HashMap<&'static str, Outcome> {
    let installed = match ctx.stat(PROGRAM_PATH) {
        Ok(_) => true,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            false
        }
        Err(e) => {
            let reason = io_reason(PROGRAM_PATH, &e);
            return KEYS
                .iter()
                .map(|(key, _)| (*key, Outcome::Unreadable(reason.clone())))
                .collect();
        }
    };
    let enabled = if installed {
        enabled(ctx)
    } else {
        Outcome::Ok(json!(false))
    };
    HashMap::from([
        ("auto_updates.installed", Outcome::Ok(json!(installed))),
        ("auto_updates.enabled", enabled),
    ])
}

fn enabled(ctx: &Ctx) -> Outcome {
    let mut command = Command::new(APT_CONFIG, &["dump"]);
    command.timeout = Duration::from_secs(10);
    command.max_output = 1024 * 1024;
    let output = match ctx.run(command) {
        Ok(output) => output,
        Err(error) => return Outcome::Unreadable(error.reason("apt-config dump")),
    };
    let settings = match parse_apt_config(&output) {
        Ok(settings) => settings,
        Err(problem) => {
            return Outcome::Unreadable(format!(
                "cannot read the output of apt-config dump: {problem}"
            ));
        }
    };
    let timers = match systemd::show(ctx, &TIMERS) {
        Ok(timers) => timers,
        Err(reason) => return Outcome::Unreadable(reason),
    };
    let timers_on = timers.iter().all(|t| {
        t.as_ref()
            .is_some_and(|t| t.is_active() && t.starts_at_boot())
    });
    Outcome::Ok(json!(settings.periodic_on() && timers_on))
}

/// The apt settings that switch automatic updates on, as `apt.systemd.daily` reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Periodic {
    /// `APT::Periodic::Enable`, the master switch: on unless set to 0 (review of #114).
    pub enable: bool,
    /// `APT::Periodic::Update-Package-Lists` is an interval that runs.
    pub update_package_lists: bool,
    /// `APT::Periodic::Unattended-Upgrade` is an interval that runs.
    pub unattended_upgrade: bool,
}

impl Periodic {
    pub fn periodic_on(&self) -> bool {
        self.enable && self.update_package_lists && self.unattended_upgrade
    }
}

/// Whether an `APT::Periodic` interval makes the job run: `always`, or a number above 0, optionally
/// with apt's unit suffix (`s`, `m`, `h`, `d`; days without one). Absent, `0`, or anything apt
/// cannot read as an interval is off (review of #114: `always` was read as 0).
fn interval_runs(value: &str) -> bool {
    if value.eq_ignore_ascii_case("always") {
        return true;
    }
    let number = value.strip_suffix(['s', 'm', 'h', 'd']).unwrap_or(value);
    number.parse::<i64>().is_ok_and(|n| n > 0)
}

/// `APT::Periodic::Enable`: `apt.systemd.daily` exits only when it is the number 0, so absent or
/// anything else leaves the job on.
fn enable_switch(value: &str) -> bool {
    !value.parse::<i64>().is_ok_and(|n| n == 0)
}

/// Reads `APT::Periodic::Enable`, `APT::Periodic::Update-Package-Lists`, and
/// `APT::Periodic::Unattended-Upgrade` from the output of `apt-config dump` (lines like
/// `APT::Periodic::Unattended-Upgrade "1";`). Names are matched without regard to case, as apt does.
pub fn parse_apt_config(output: &[u8]) -> Result<Periodic, String> {
    let text = std::str::from_utf8(output).map_err(|_| "the output is not valid UTF-8")?;
    let mut periodic = Periodic {
        enable: true,
        update_package_lists: false,
        unattended_upgrade: false,
    };
    let mut any = false;
    for line in text.lines() {
        let Some((name, rest)) = line.trim().split_once(char::is_whitespace) else {
            continue;
        };
        any = true;
        let value = rest
            .trim()
            .trim_end_matches(';')
            .trim()
            .trim_matches('"')
            .trim();
        if name.eq_ignore_ascii_case("APT::Periodic::Enable") {
            periodic.enable = enable_switch(value);
        } else if name.eq_ignore_ascii_case("APT::Periodic::Update-Package-Lists") {
            periodic.update_package_lists = interval_runs(value);
        } else if name.eq_ignore_ascii_case("APT::Periodic::Unattended-Upgrade") {
            periodic.unattended_upgrade = interval_runs(value);
        }
    }
    if !any {
        return Err("the output is empty".into());
    }
    Ok(periodic)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ON: &[u8] = include_bytes!("../../tests/fixtures/facts/debian13/apt-config-dump.auto");
    const OFF: &[u8] = include_bytes!("../../tests/fixtures/facts/debian13/apt-config-dump.stock");

    #[test]
    fn periodic_settings_from_apt_config_dump() {
        let on = parse_apt_config(ON).unwrap();
        assert_eq!(
            on,
            Periodic {
                enable: true,
                update_package_lists: true,
                unattended_upgrade: true
            }
        );
        assert!(on.periodic_on());
        let off = parse_apt_config(OFF).unwrap();
        assert_eq!(
            off,
            Periodic {
                enable: true,
                update_package_lists: false,
                unattended_upgrade: false
            }
        );
        assert!(!off.periodic_on());
    }

    #[test]
    fn the_master_switch_turns_everything_off() {
        // Review of #114: `APT::Periodic::Enable "0"` stops apt.systemd.daily whatever the intervals.
        let text = b"APT::Periodic::Enable \"0\";\nAPT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n";
        let parsed = parse_apt_config(text).unwrap();
        assert!(!parsed.enable);
        assert!(!parsed.periodic_on());
        for value in ["1", "yes", ""] {
            let text = format!(
                "APT::Periodic::Enable \"{value}\";\nAPT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
            );
            assert!(
                parse_apt_config(text.as_bytes()).unwrap().periodic_on(),
                "{value:?}"
            );
        }
    }

    #[test]
    fn always_and_unit_suffixes_are_intervals_that_run() {
        // Review of #114: `always` was read as 0, so the host was reported as not updating itself.
        for value in ["always", "Always", "1d", "12h", "30m", "3600s", "7"] {
            let text = format!(
                "APT::Periodic::Update-Package-Lists \"{value}\";\nAPT::Periodic::Unattended-Upgrade \"{value}\";\n"
            );
            assert!(
                parse_apt_config(text.as_bytes()).unwrap().periodic_on(),
                "{value:?}"
            );
        }
    }

    #[test]
    fn values_that_are_zero_or_not_numbers_are_off() {
        for value in ["0", "never", "", "-1", "0d", "d"] {
            let text = format!(
                "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"{value}\";\n"
            );
            assert!(
                !parse_apt_config(text.as_bytes()).unwrap().periodic_on(),
                "{value:?}"
            );
        }
        let days = b"apt::periodic::update-package-lists \"7\";\nApt::Periodic::Unattended-Upgrade \"3\";\n";
        assert!(parse_apt_config(days).unwrap().periodic_on());
    }

    #[test]
    fn unusable_output_is_an_error() {
        assert!(parse_apt_config(b"").is_err());
        assert!(parse_apt_config(b"\xff").is_err());
    }
}
