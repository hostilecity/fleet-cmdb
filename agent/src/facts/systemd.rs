//! systemd unit state through `systemctl` (P2-A03, P2-A02): the state of named units, and the lists of
//! running and enabled services.
//!
//! Every command is read-only, from `/usr/bin/systemctl` (or `/bin/systemctl`), with fixed
//! arguments. Unit names, which come from the manifest, go only after `--` and only after
//! [`valid_unit`] has checked them: a name that starts with `-`, has a character outside the unit
//! name alphabet, or lacks a unit type suffix is never passed to a command, so a hostile manifest
//! cannot smuggle an option into `systemctl`. The manifest names units; nothing here ever starts,
//! stops, or runs one.
//!
//! - [`show`]: `systemctl show --property=LoadState,ActiveState,UnitFileState -- UNIT...`. It prints one
//!   block of `Name=value` lines per unit, in the order the units were given, and exits `0` even for a
//!   unit that does not exist (`LoadState=not-found`), which is a fact too: no such unit (`null`).
//! - [`running`]: `systemctl list-units --type=service --state=running`.
//! - [`enabled`]: `systemctl list-unit-files --type=service --state=enabled`.
//!
//! The parsers are pure functions over the command's output.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::{Value, json};

use super::host::Command;
use super::{Ctx, Outcome};

const PROGRAMS: &[&str] = &["/usr/bin/systemctl", "/bin/systemctl"];
const TIMEOUT: Duration = Duration::from_secs(10);
/// Units asked about in one `systemctl show`, so the command line stays short.
const CHUNK: usize = 40;
/// Most output kept from a service listing: far above 1000 units' worth.
const MAX_LIST_OUTPUT: usize = 4 * 1024 * 1024;

const UNIT_TYPES: &[&str] = &[
    ".service",
    ".socket",
    ".timer",
    ".target",
    ".path",
    ".mount",
    ".automount",
    ".swap",
    ".slice",
];

/// Whether `name` is safe to hand to `systemctl` as a unit name: 1 to 100 characters from the unit
/// name alphabet (as the manifest schema has it), ending in a unit type suffix, and not starting
/// with `-` or `.`.
pub fn valid_unit(name: &str) -> bool {
    (1..=100).contains(&name.len())
        && !name.starts_with(['-', '.'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'+' | b'-'))
        && UNIT_TYPES.iter().any(|suffix| name.ends_with(suffix))
}

/// What systemd says about one loaded unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitInfo {
    pub active: String,
    /// `UnitFileState`: `enabled`, `disabled`, `static`, `masked`, ...
    pub enabled: String,
}

impl UnitInfo {
    /// `ActiveState=active`.
    pub fn is_active(&self) -> bool {
        self.active == "active"
    }

    /// Set to start at boot: `UnitFileState=enabled` only (review of #114). `enabled-runtime` links
    /// live under `/run` and are gone after a reboot; `static`, `alias`, and `generated` say how the
    /// unit file is installed, not that anything pulls the unit in at boot. A false "starts at boot"
    /// would report a firewall or automatic updates as protecting a host they may not protect.
    pub fn starts_at_boot(&self) -> bool {
        self.enabled == "enabled"
    }
}

/// The state of each of `units` (`None` for a unit systemd does not know), or why it could not be
/// read. Every name must satisfy [`valid_unit`].
pub fn show(ctx: &Ctx, units: &[&str]) -> Result<Vec<Option<UnitInfo>>, String> {
    let mut all = Vec::with_capacity(units.len());
    for chunk in units.chunks(CHUNK) {
        debug_assert!(chunk.iter().all(|u| valid_unit(u)));
        let mut args = vec![
            "show",
            "--no-pager",
            "--property=LoadState,ActiveState,UnitFileState",
            "--",
        ];
        args.extend(chunk.iter().copied());
        let mut command = Command::new(PROGRAMS, &args);
        command.timeout = TIMEOUT;
        let output = ctx
            .run(command)
            .map_err(|error| error.reason("systemctl show"))?;
        all.extend(parse_show(&output, chunk.len())?);
    }
    Ok(all)
}

/// The blocks of `systemctl show` output, one per unit asked about.
pub fn parse_show(output: &[u8], expected: usize) -> Result<Vec<Option<UnitInfo>>, String> {
    let text = std::str::from_utf8(output)
        .map_err(|_| "systemctl show printed something that is not UTF-8".to_owned())?;
    let mut blocks: Vec<HashMap<&str, &str>> = Vec::new();
    let mut current: HashMap<&str, &str> = HashMap::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !current.is_empty() {
                blocks.push(std::mem::take(&mut current));
            }
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            current.insert(name, value);
        }
    }
    if !current.is_empty() {
        blocks.push(current);
    }
    if blocks.len() != expected {
        return Err(format!(
            "systemctl show described {} units when {expected} were asked about",
            blocks.len()
        ));
    }
    blocks
        .into_iter()
        .map(|block| {
            let load = block.get("LoadState").copied().unwrap_or("");
            let active = block.get("ActiveState").copied().unwrap_or("");
            let enabled = block.get("UnitFileState").copied().unwrap_or("");
            if load.is_empty() || active.is_empty() {
                return Err("systemctl show did not print LoadState and ActiveState".to_owned());
            }
            if load == "not-found" {
                return Ok(None);
            }
            Ok(Some(UnitInfo {
                active: active.to_owned(),
                enabled: enabled.to_owned(),
            }))
        })
        .collect()
}

/// A `service_state` fact value for a unit, or an outcome that says why there is none.
pub fn state_outcome(unit: &str, info: Option<&UnitInfo>) -> Outcome {
    match info {
        None => Outcome::Ok(Value::Null),
        Some(info) if info.enabled.is_empty() => Outcome::Unreadable(format!(
            "systemd reports no unit file state for {unit} (a transient unit has none)"
        )),
        Some(info) => Outcome::Ok(json!({"active": info.active, "enabled": info.enabled})),
    }
}

/// Names of the running service units, sorted.
pub fn running(ctx: &Ctx) -> Result<Vec<String>, String> {
    listing(
        ctx,
        &[
            "list-units",
            "--type=service",
            "--state=running",
            "--plain",
            "--no-legend",
            "--no-pager",
            "--full",
        ],
        "systemctl list-units",
    )
}

/// Names of the service unit files enabled to start at boot, sorted. Template units (`getty@.service`)
/// are included as systemd lists them.
pub fn enabled(ctx: &Ctx) -> Result<Vec<String>, String> {
    listing(
        ctx,
        &[
            "list-unit-files",
            "--type=service",
            "--state=enabled",
            "--plain",
            "--no-legend",
            "--no-pager",
            "--full",
        ],
        "systemctl list-unit-files",
    )
}

fn listing(ctx: &Ctx, args: &[&str], what: &str) -> Result<Vec<String>, String> {
    let mut command = Command::new(PROGRAMS, args);
    command.timeout = TIMEOUT;
    command.max_output = MAX_LIST_OUTPUT;
    let output = ctx.run(command).map_err(|error| error.reason(what))?;
    parse_listing(&output).map_err(|problem| format!("cannot read the output of {what}: {problem}"))
}

/// Whether a name systemd printed in a listing is a service unit name. Looser than [`valid_unit`],
/// which guards what goes *into* a command: systemd's own names may be escaped
/// (`systemd-fsck@dev-disk-by\x2duuid-….service`) or longer than the manifest's 100 characters, and
/// one such name must not make the whole list unreadable (review of #114). The report's limits on
/// items are still applied when the fact is finalized.
fn listed_service(name: &str) -> bool {
    name.len() > ".service".len()
        && name.ends_with(".service")
        && !name.starts_with('-')
        && !name.chars().any(char::is_control)
}

/// The first column of a `systemctl list-units` or `list-unit-files` listing without a legend: the
/// unit names, sorted, each once. A line that does not start with a unit name is an error, so a
/// format change shows up as unreadable rather than as a wrong list.
pub fn parse_listing(output: &[u8]) -> Result<Vec<String>, String> {
    let text = std::str::from_utf8(output).map_err(|_| "the output is not valid UTF-8")?;
    let mut names: Vec<String> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        // systemd marks failed units with a leading bullet unless `--plain` removed it.
        let line = line.trim().trim_start_matches(['●', '*']).trim_start();
        if line.is_empty() {
            continue;
        }
        let name = line.split_whitespace().next().unwrap_or("");
        if !listed_service(name) {
            return Err(format!(
                "line {} does not start with a service unit name",
                index + 1
            ));
        }
        names.push(name.to_owned());
    }
    names.sort();
    names.dedup();
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHOW: &[u8] = include_bytes!("../../tests/fixtures/facts/debian13/systemctl-show");
    const RUNNING: &[u8] = include_bytes!("../../tests/fixtures/facts/debian13/systemctl-running");
    const ENABLED: &[u8] = include_bytes!("../../tests/fixtures/facts/debian13/systemctl-enabled");

    #[test]
    fn unit_names_are_checked_before_they_reach_a_command() {
        for name in [
            "ssh.service",
            "telnet.socket",
            "getty@tty1.service",
            "apt-daily.timer",
            "systemd-journald.service",
            "a+b_c.service",
        ] {
            assert!(valid_unit(name), "{name}");
        }
        for name in [
            "",
            "--help",
            "-H",
            "--host=evil.example.lan",
            ".hidden.service",
            "ssh",
            "ssh.service; reboot",
            "ssh.service\n",
            "a b.service",
            "../x.service",
            "x/y.service",
            "ssh.conf",
            "ssh.service.bak",
            &format!("{}.service", "a".repeat(100)),
        ] {
            assert!(!valid_unit(name), "{name:?}");
        }
    }

    #[test]
    fn show_output_is_read_in_the_order_the_units_were_given() {
        let states = parse_show(SHOW, 5).unwrap();
        assert_eq!(
            states[0],
            Some(UnitInfo {
                active: "active".into(),
                enabled: "enabled".into()
            })
        );
        assert_eq!(
            states[1],
            Some(UnitInfo {
                active: "inactive".into(),
                enabled: "disabled".into()
            })
        );
        assert_eq!(
            states[2],
            Some(UnitInfo {
                active: "inactive".into(),
                enabled: "masked".into()
            })
        );
        assert_eq!(states[3], None, "a unit systemd does not know is null");
        assert_eq!(
            states[4],
            Some(UnitInfo {
                active: "active".into(),
                enabled: "static".into()
            })
        );
    }

    #[test]
    fn a_wrong_number_of_blocks_is_an_error_not_a_misaligned_answer() {
        assert!(parse_show(SHOW, 4).is_err());
        assert!(parse_show(SHOW, 6).is_err());
        assert!(parse_show(b"", 1).is_err());
        assert!(parse_show(b"\xff", 1).is_err());
        assert!(parse_show(b"Description=x\n", 1).is_err());
    }

    #[test]
    fn state_outcomes() {
        let info = UnitInfo {
            active: "active".into(),
            enabled: "enabled".into(),
        };
        assert_eq!(
            state_outcome("ssh.service", Some(&info)),
            Outcome::Ok(json!({"active": "active", "enabled": "enabled"}))
        );
        assert_eq!(state_outcome("x.service", None), Outcome::Ok(Value::Null));
        let transient = UnitInfo {
            active: "active".into(),
            enabled: String::new(),
        };
        assert!(matches!(
            state_outcome("run-1.service", Some(&transient)),
            Outcome::Unreadable(_)
        ));
    }

    #[test]
    fn starts_at_boot_and_is_active() {
        let unit = |active: &str, enabled: &str| UnitInfo {
            active: active.into(),
            enabled: enabled.into(),
        };
        assert!(unit("active", "enabled").is_active());
        assert!(!unit("inactive", "enabled").is_active());
        assert!(!unit("activating", "enabled").is_active());
        assert!(unit("active", "enabled").starts_at_boot());
        // Review of #114: none of these persists or proves a boot dependency.
        for enabled in [
            "enabled-runtime",
            "static",
            "alias",
            "generated",
            "disabled",
            "masked",
            "masked-runtime",
            "linked",
            "indirect",
            "",
        ] {
            assert!(!unit("active", enabled).starts_at_boot(), "{enabled}");
        }
    }

    #[test]
    fn listings_are_sorted_unique_service_names() {
        let running = parse_listing(RUNNING).unwrap();
        assert_eq!(running.first().map(String::as_str), Some("cron.service"));
        assert!(running.contains(&"ssh.service".to_owned()));
        assert!(running.windows(2).all(|w| w[0] < w[1]));
        let enabled = parse_listing(ENABLED).unwrap();
        assert!(enabled.contains(&"getty@.service".to_owned()));
        assert!(enabled.contains(&"unattended-upgrades.service".to_owned()));
        assert!(parse_listing(b"").unwrap().is_empty());
    }

    #[test]
    fn escaped_and_long_names_from_systemd_are_kept_in_a_listing() {
        // Review of #114: the manifest's unit-name rule made one escaped name fail the whole list.
        let long = format!("{}.service", "a".repeat(120));
        let text = format!(
            "cron.service loaded active running Regular background program processing daemon\n\
             systemd-fsck@dev-disk-by\\x2duuid-0123.service loaded active running File System Check\n\
             {long} loaded active running Long\n"
        );
        let names = parse_listing(text.as_bytes()).unwrap();
        assert_eq!(names.len(), 3, "{names:?}");
        assert!(names.contains(&"systemd-fsck@dev-disk-by\\x2duuid-0123.service".to_owned()));
        assert!(names.contains(&long));
        // Still refused: what is not a service unit name.
        assert!(parse_listing(b"ssh.socket loaded active running\n").is_err());
        assert!(parse_listing(b"0 loaded units listed.\n").is_err());
        assert!(parse_listing(b".service x\n").is_err());
    }

    #[test]
    fn a_listing_with_something_else_in_it_is_an_error() {
        for output in [
            &b"ssh.service loaded active running OpenBSD Secure Shell server\n12 loaded units listed.\n"[..],
            b"--help\n",
            b"ssh.socket enabled enabled\n",
            b"\xff\n",
        ] {
            assert!(parse_listing(output).is_err(), "{output:?}");
        }
        assert_eq!(
            parse_listing("● failed.service loaded failed failed X\n".as_bytes()).unwrap(),
            ["failed.service"]
        );
    }
}
