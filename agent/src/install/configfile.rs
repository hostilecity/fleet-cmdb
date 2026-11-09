//! The config file `install` writes (P1-A10, FR-1.6): the server URL and the credential, with every
//! other setting either carried over from the existing config or left as a commented default.
//!
//! The text is checked by parsing it with [`Config::from_toml`] before it is written, so the installer
//! can never write a config the agent would refuse.

use std::path::Path;

use crate::config::{Config, Credential, DEFAULT_STATE_DIR, Interval, LogLevel};
use crate::tasks::settings::TaskSettings;

/// Settings carried over from an existing config when the credential or server changes.
#[derive(Debug, Clone)]
pub struct Carried {
    pub log_level: LogLevel,
    pub state_dir: Option<String>,
    pub heartbeat: Option<Interval>,
    pub inventory: Option<Interval>,
    pub config_report: Option<Interval>,
    pub task_poll: Option<Interval>,
    /// `update_confirm_seconds` when it is not the default (P1-AGENT-UPDATE).
    pub update_confirm_seconds: Option<u64>,
    /// The `[tasks]` settings (P3-A01), so re-running the installer never turns a task on or off.
    pub tasks: TaskSettings,
}

impl Carried {
    /// The settings in `config` that differ from the defaults.
    pub fn from(config: &Config) -> Self {
        let defaults = defaults();
        Self {
            log_level: config.log_level,
            state_dir: (config.state_dir != Path::new(DEFAULT_STATE_DIR))
                .then(|| config.state_dir.to_string_lossy().into_owned()),
            heartbeat: (config.heartbeat != defaults.heartbeat).then_some(config.heartbeat),
            inventory: (config.inventory != defaults.inventory).then_some(config.inventory),
            config_report: (config.config_report != defaults.config_report)
                .then_some(config.config_report),
            task_poll: (config.task_poll != defaults.task_poll).then_some(config.task_poll),
            update_confirm_seconds: (config.update_confirm_seconds
                != defaults.update_confirm_seconds)
                .then_some(config.update_confirm_seconds),
            tasks: config.tasks.clone(),
        }
    }

    pub fn none() -> Self {
        Self {
            log_level: LogLevel::Info,
            state_dir: None,
            heartbeat: None,
            inventory: None,
            config_report: None,
            task_poll: None,
            update_confirm_seconds: None,
            tasks: TaskSettings::default(),
        }
    }
}

fn defaults() -> Config {
    Config::from_toml(
        "server_url = \"https://agent.example.lan\"\ncredential = \"EXAMPLEkey01.EXAMPLE-secret-not-a-real-credential-0001\"\n",
    )
    .expect("the default config parses")
}

/// A TOML basic string. Control characters are escaped, so no value can end the line early.
fn quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn interval(name: &str, value: Option<&Interval>, defaults: &Interval, out: &mut String) {
    match value {
        Some(i) => out.push_str(&format!(
            "\n[{name}]\ninterval_seconds = {}\nmin_seconds = {}\nmax_seconds = {}\n",
            i.start.as_secs(),
            i.min.as_secs(),
            i.max.as_secs()
        )),
        None => out.push_str(&format!(
            "\n# [{name}]                                # seconds; defaults shown\n# interval_seconds = {}\n# min_seconds = {}\n# max_seconds = {}\n",
            defaults.start.as_secs(),
            defaults.min.as_secs(),
            defaults.max.as_secs()
        )),
    }
}

/// A TOML array of basic strings.
fn quoted_list(values: &[String]) -> String {
    let items: Vec<String> = values.iter().map(|v| quoted(v)).collect();
    format!("[{}]", items.join(", "))
}

/// The `[tasks]` section. Settings that were refused are not carried: every task stays off, as it
/// was, and a comment says why (P3-A01: invalid task configuration fails safe).
fn tasks(settings: &TaskSettings, out: &mut String) {
    if let Some(problem) = settings.problem() {
        let problem: String = problem
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        out.push_str(&format!(
            "\n# The [tasks] section here before was not valid, so it was not kept and every task stays off:\n# {problem}\n[tasks]\nenabled = []\n"
        ));
        return;
    }
    if settings.uses_default_types() && settings.allowed_services().is_empty() {
        out.push_str(
            "\n# [tasks]                                    # remote tasks (DEC-14, DEC-15); defaults shown\n# enabled = [\"refresh_reports\"]            # also restart_service, apply_package_updates\n# allowed_services = []                      # units restart_service may restart\n",
        );
        return;
    }
    out.push_str("\n[tasks]\n");
    if !settings.uses_default_types() {
        out.push_str(&format!("enabled = {}\n", quoted_list(settings.enabled())));
    }
    if !settings.allowed_services().is_empty() {
        out.push_str(&format!(
            "allowed_services = {}\n",
            quoted_list(settings.allowed_services())
        ));
    }
}

/// The config text. `ca_file` must be valid UTF-8 (checked in preflight).
pub fn render(
    server_url: &str,
    credential: &Credential,
    ca_file: Option<&Path>,
    carried: &Carried,
) -> Result<String, String> {
    let defaults = defaults();
    let mut out = String::from(
        "# fleet-agent configuration, written by `fleet-agent install`.\n\
         # It holds this host's credential: keep it root-owned with mode 0600 and never copy it to\n\
         # another host. Check changes with `fleet-agent check-config`; unknown keys are refused.\n\n",
    );
    out.push_str(&format!("server_url = {}\n", quoted(server_url)));
    out.push_str(&format!(
        "credential = {}\n",
        quoted(credential.expose_secret())
    ));
    match carried.log_level {
        LogLevel::Info => out.push_str(
            "# log_level = \"info\"                     # error, warn, info, debug, trace\n",
        ),
        level => out.push_str(&format!("log_level = {}\n", quoted(level.as_str()))),
    }
    match ca_file {
        Some(path) => {
            let path = path.to_str().ok_or("the CA file path is not valid UTF-8")?;
            out.push_str(&format!("ca_file = {}\n", quoted(path)));
        }
        None => out.push_str(
            "# ca_file = \"/etc/fleet-agent/ca.pem\"     # extra CA bundle for a private CA\n",
        ),
    }
    match &carried.state_dir {
        Some(dir) => out.push_str(&format!("state_dir = {}\n", quoted(dir))),
        None => out.push_str(&format!("# state_dir = {}\n", quoted(DEFAULT_STATE_DIR))),
    }
    match carried.update_confirm_seconds {
        Some(seconds) => out.push_str(&format!("update_confirm_seconds = {seconds}\n")),
        None => out.push_str(&format!(
            "# update_confirm_seconds = {}             # how long a new version has to confirm an update\n",
            defaults.update_confirm_seconds
        )),
    }
    interval(
        "heartbeat",
        carried.heartbeat.as_ref(),
        &defaults.heartbeat,
        &mut out,
    );
    interval(
        "inventory",
        carried.inventory.as_ref(),
        &defaults.inventory,
        &mut out,
    );
    interval(
        "config_report",
        carried.config_report.as_ref(),
        &defaults.config_report,
        &mut out,
    );
    interval(
        "task_poll",
        carried.task_poll.as_ref(),
        &defaults.task_poll,
        &mut out,
    );
    tasks(&carried.tasks, &mut out);
    // Never write a config the agent would refuse. The parse error never contains the credential.
    Config::from_toml(&out).map_err(|e| format!("the config to be written is not valid: {e}"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::{CREDENTIAL, minimal};
    use std::time::Duration;

    #[test]
    fn a_fresh_config_parses_to_the_defaults() {
        let text = render(
            "https://agent.example.lan",
            &Credential::new(CREDENTIAL),
            None,
            &Carried::none(),
        )
        .unwrap();
        let config = Config::from_toml(&text).unwrap();
        let defaults = defaults();
        assert_eq!(config.server_url, "https://agent.example.lan");
        assert_eq!(config.credential.expose_secret(), CREDENTIAL);
        assert_eq!(config.heartbeat, defaults.heartbeat);
        assert_eq!(config.inventory, defaults.inventory);
        assert_eq!(config.ca_file, None);
        assert!(text.contains("# [heartbeat]"));
    }

    #[test]
    fn custom_settings_are_carried_over() {
        let old = Config::from_toml(&format!(
            "{}log_level = \"debug\"\nstate_dir = \"/srv/agent \\\"state\\\"\"\nupdate_confirm_seconds = 120\n[heartbeat]\ninterval_seconds = 120\n[task_poll]\ninterval_seconds = 60\n",
            minimal()
        ))
        .unwrap();
        let carried = Carried::from(&old);
        assert!(carried.inventory.is_none());
        let text = render(
            "https://agent2.example.lan",
            &Credential::new(CREDENTIAL),
            Some(Path::new("/etc/fleet-agent/ca \"x\".pem")),
            &carried,
        )
        .unwrap();
        let new = Config::from_toml(&text).unwrap();
        assert_eq!(new.log_level, LogLevel::Debug);
        assert_eq!(new.state_dir, old.state_dir);
        assert_eq!(new.heartbeat, old.heartbeat);
        assert_eq!(new.heartbeat.start, Duration::from_secs(120));
        assert_eq!(new.inventory, old.inventory);
        assert_eq!(new.config_report, old.config_report);
        assert_eq!(new.task_poll.start, Duration::from_secs(60));
        // Review of the VM tests (P1-AGENT-UPDATE): a re-run of the installer used to drop it.
        assert_eq!(new.update_confirm_seconds, 120);
        assert_eq!(
            new.ca_file.unwrap(),
            Path::new("/etc/fleet-agent/ca \"x\".pem")
        );
    }

    #[test]
    fn task_settings_are_carried_over_and_a_bad_section_stays_off() {
        let render_from = |tasks: &str| {
            let old = Config::from_toml(&format!("{}{tasks}", minimal())).unwrap();
            let text = render(
                "https://agent.example.lan",
                &Credential::new(CREDENTIAL),
                None,
                &Carried::from(&old),
            )
            .unwrap();
            (old, Config::from_toml(&text).unwrap(), text)
        };
        for tasks in [
            "",
            "[tasks]\nenabled = []\n",
            "[tasks]\nenabled = [\"restart_service\", \"apply_package_updates\"]\nallowed_services = [\"nginx.service\", \"app@blue.service\"]\n",
            "[tasks]\nallowed_services = [\"nginx.service\"]\n",
        ] {
            let (old, new, _) = render_from(tasks);
            assert_eq!(new.tasks, old.tasks, "{tasks}");
        }
        let (_, new, text) = render_from("[tasks]\nenabled = [\"reboot\"]\n");
        assert_eq!(new.tasks.problem(), None);
        assert!(new.tasks.enabled().is_empty());
        assert!(text.contains("was not valid"), "{text}");
        assert!(text.contains("`reboot`"), "{text}");
        let (_, _, text) = render_from("");
        assert!(text.contains("# [tasks]"), "{text}");
    }

    #[test]
    fn control_characters_cannot_break_out_of_a_value() {
        let text = render(
            "https://agent.example.lan",
            &Credential::new(CREDENTIAL),
            Some(Path::new("/tmp/a\nserver_url = \"x\"")),
            &Carried::none(),
        )
        .unwrap();
        assert_eq!(
            Config::from_toml(&text).unwrap().ca_file.unwrap(),
            Path::new("/tmp/a\nserver_url = \"x\"")
        );
    }
}
