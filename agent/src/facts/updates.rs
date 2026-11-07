//! Automatic updates (P2-A02): `auto_updates.installed` and `auto_updates.enabled`, for the
//! mechanism of Debian 13, `unattended-upgrades` and its apt timers (DEC-01).
//!
//! - `installed`: `/usr/bin/unattended-upgrade`, the program the package ships, exists.
//! - `enabled`: installed, and all of
//!   - `APT::Periodic::Update-Package-Lists` is above 0 and `APT::Periodic::Unattended-Upgrade` is
//!     above 0 in apt's effective configuration (`apt-config dump`, read-only, fixed arguments; apt
//!     reads a value that is not a number as 0);
//!   - `apt-daily.timer` and `apt-daily-upgrade.timer` are active and start at boot.
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

/// The apt settings that switch automatic updates on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Periodic {
    pub update_package_lists: i64,
    pub unattended_upgrade: i64,
}

impl Periodic {
    pub fn periodic_on(&self) -> bool {
        self.update_package_lists > 0 && self.unattended_upgrade > 0
    }
}

/// Reads `APT::Periodic::Update-Package-Lists` and `APT::Periodic::Unattended-Upgrade` from the
/// output of `apt-config dump` (lines like `APT::Periodic::Unattended-Upgrade "1";`). Names are
/// matched without regard to case, as apt does; a setting that is absent or not a number is 0.
pub fn parse_apt_config(output: &[u8]) -> Result<Periodic, String> {
    let text = std::str::from_utf8(output).map_err(|_| "the output is not valid UTF-8")?;
    let mut periodic = Periodic {
        update_package_lists: 0,
        unattended_upgrade: 0,
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
            .trim()
            .parse::<i64>()
            .unwrap_or(0);
        if name.eq_ignore_ascii_case("APT::Periodic::Update-Package-Lists") {
            periodic.update_package_lists = value;
        } else if name.eq_ignore_ascii_case("APT::Periodic::Unattended-Upgrade") {
            periodic.unattended_upgrade = value;
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
                update_package_lists: 1,
                unattended_upgrade: 1
            }
        );
        assert!(on.periodic_on());
        let off = parse_apt_config(OFF).unwrap();
        assert_eq!(
            off,
            Periodic {
                update_package_lists: 0,
                unattended_upgrade: 0
            }
        );
        assert!(!off.periodic_on());
    }

    #[test]
    fn values_that_are_zero_or_not_numbers_are_off() {
        for value in ["0", "never", "", "-1"] {
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
