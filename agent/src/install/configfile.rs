//! The config file `install` writes (P1-A10, FR-1.6): the server URL and the credential, with every
//! other setting either carried over from the existing config or left as a commented default.
//!
//! The text is checked by parsing it with [`Config::from_toml`] before it is written, so the installer
//! can never write a config the agent would refuse.

use std::path::Path;

use crate::config::{Config, Credential, DEFAULT_STATE_DIR, Interval, LogLevel};

/// Settings carried over from an existing config when the credential or server changes.
#[derive(Debug, Clone)]
pub struct Carried {
    pub log_level: LogLevel,
    pub state_dir: Option<String>,
    pub heartbeat: Option<Interval>,
    pub inventory: Option<Interval>,
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
        }
    }

    pub fn none() -> Self {
        Self {
            log_level: LogLevel::Info,
            state_dir: None,
            heartbeat: None,
            inventory: None,
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
            "{}log_level = \"debug\"\nstate_dir = \"/srv/agent \\\"state\\\"\"\n[heartbeat]\ninterval_seconds = 120\n",
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
        assert_eq!(
            new.ca_file.unwrap(),
            Path::new("/etc/fleet-agent/ca \"x\".pem")
        );
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
