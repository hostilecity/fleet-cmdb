//! SSH server settings (P2-A02): the effective values from `sshd -T`.
//!
//! `sshd -T` prints the configuration sshd would run with, after reading `sshd_config` and every file
//! it includes (Debian's `sshd_config.d/*.conf` drop-ins), one `keyword value` line per setting,
//! keywords in lower case. That is the only source: if the command cannot run (sshd not installed,
//! permission denied, a timeout, a failure) every `sshd.*` fact is `unreadable` with the reason, and
//! the configuration files are never parsed as a substitute, because a guess from the files can
//! disagree with what sshd really does (an `Include` order, a `Match` block, a built-in default).
//!
//! The command is exactly `sshd -T`: a fixed program path (`/usr/sbin/sshd`, `/sbin/sshd`), the
//! single fixed argument, no `-f`, no `-C`, no shell, ten seconds and 1 MiB at most. Without `-C`
//! the global values are printed; `Match` blocks, which need a connection to evaluate, are not
//! applied. Only the keywords in [`FACTS`] are taken from the output; nothing else sshd prints (host
//! key paths, `AuthorizedKeysFile`, and so on) is kept.
//!
//! Parsing ([`parse`], [`convert`]) is separate from reading ([`read`]), and is a pure function over
//! the command's output.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::{Value, json};

use super::manifest::FactType;
use super::{Ctx, Outcome};
use crate::facts::host::Command;

const PROGRAMS: &[&str] = &["/usr/sbin/sshd", "/sbin/sshd"];
const WHAT: &str = "sshd -T";
const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_OUTPUT: usize = 1024 * 1024;

/// How a keyword's value becomes a fact value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// `PermitRootLogin`: one of four words; the old spelling `without-password` is `prohibit-password`.
    RootLogin,
    /// Any single word or path, as printed.
    Text,
    /// `yes` or `no`.
    Bool,
    /// A whole number.
    Int,
    /// Comma-separated, in the order sshd prints them (which is the order it offers them).
    List,
}

/// The facts read from `sshd -T`: the manifest key, its type, and how to convert the value. The
/// keyword is the key after `sshd.`.
const FACTS: &[(&str, FactType, Kind)] = &[
    ("sshd.permitrootlogin", FactType::String, Kind::RootLogin),
    ("sshd.passwordauthentication", FactType::Boolean, Kind::Bool),
    ("sshd.permitemptypasswords", FactType::Boolean, Kind::Bool),
    ("sshd.pubkeyauthentication", FactType::Boolean, Kind::Bool),
    (
        "sshd.hostbasedauthentication",
        FactType::Boolean,
        Kind::Bool,
    ),
    ("sshd.ignorerhosts", FactType::Boolean, Kind::Bool),
    ("sshd.permituserenvironment", FactType::Boolean, Kind::Bool),
    ("sshd.x11forwarding", FactType::Boolean, Kind::Bool),
    ("sshd.usepam", FactType::Boolean, Kind::Bool),
    ("sshd.allowtcpforwarding", FactType::String, Kind::Text),
    ("sshd.loglevel", FactType::String, Kind::Text),
    ("sshd.maxauthtries", FactType::Integer, Kind::Int),
    ("sshd.maxsessions", FactType::Integer, Kind::Int),
    ("sshd.logingracetime", FactType::Integer, Kind::Int),
    ("sshd.clientaliveinterval", FactType::Integer, Kind::Int),
    ("sshd.clientalivecountmax", FactType::Integer, Kind::Int),
    ("sshd.banner", FactType::String, Kind::Text),
    ("sshd.ciphers", FactType::StringList, Kind::List),
    ("sshd.macs", FactType::StringList, Kind::List),
    ("sshd.kexalgorithms", FactType::StringList, Kind::List),
];

/// The manifest keys this reader answers, with their types.
pub fn keys() -> impl Iterator<Item = (&'static str, FactType)> {
    FACTS.iter().map(|(key, ty, _)| (*key, ty.clone()))
}

/// Runs `sshd -T` and converts the output; every key is `unreadable` if it cannot.
pub fn read(ctx: &Ctx) -> HashMap<&'static str, Outcome> {
    let mut command = Command::new(PROGRAMS, &["-T"]);
    command.timeout = TIMEOUT;
    command.max_output = MAX_OUTPUT;
    match ctx.run(command) {
        Ok(output) => convert(&output),
        Err(error) => {
            let reason = error.reason(WHAT);
            FACTS
                .iter()
                .map(|(key, _, _)| (*key, Outcome::Unreadable(reason.clone())))
                .collect()
        }
    }
}

/// Converts the output of `sshd -T` into the facts of [`FACTS`].
pub fn convert(output: &[u8]) -> HashMap<&'static str, Outcome> {
    let parsed = match parse(output) {
        Ok(parsed) => parsed,
        Err(reason) => {
            let reason = format!("cannot read the output of {WHAT}: {reason}");
            return FACTS
                .iter()
                .map(|(key, _, _)| (*key, Outcome::Unreadable(reason.clone())))
                .collect();
        }
    };
    FACTS
        .iter()
        .map(|(key, _, kind)| {
            let keyword = key.strip_prefix("sshd.").unwrap_or(key);
            let outcome = match parsed.get(keyword).map(Vec::as_slice) {
                None => Outcome::Unreadable(format!("{WHAT} did not print `{keyword}`")),
                Some([value]) => match value_of(*kind, value) {
                    Ok(value) => Outcome::Ok(value),
                    Err(problem) => Outcome::Unreadable(format!("`{keyword}`: {problem}")),
                },
                Some(_) => Outcome::Unreadable(format!(
                    "{WHAT} printed `{keyword}` more than once; cannot tell which applies"
                )),
            };
            (*key, outcome)
        })
        .collect()
}

/// The lines of `sshd -T` output: keyword (lower-cased) to the values printed for it. A keyword
/// printed more than once (`port`, `hostkey`, `listenaddress`) keeps every value.
pub fn parse(output: &[u8]) -> Result<HashMap<String, Vec<String>>, String> {
    let text = std::str::from_utf8(output).map_err(|_| "the output is not valid UTF-8")?;
    let mut parsed: HashMap<String, Vec<String>> = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (keyword, value) = match line.split_once(char::is_whitespace) {
            Some((keyword, value)) => (keyword, value.trim()),
            None => (line, ""),
        };
        parsed
            .entry(keyword.to_ascii_lowercase())
            .or_default()
            .push(value.to_owned());
    }
    if parsed.is_empty() {
        return Err("the output is empty".into());
    }
    Ok(parsed)
}

fn value_of(kind: Kind, text: &str) -> Result<Value, String> {
    match kind {
        Kind::RootLogin => match text {
            "yes" | "no" | "prohibit-password" | "forced-commands-only" => Ok(json!(text)),
            "without-password" => Ok(json!("prohibit-password")),
            other => Err(format!(
                "unexpected value `{}`",
                crate::logging::sanitize(other, 32)
            )),
        },
        Kind::Text if text.is_empty() => Err("no value".into()),
        Kind::Text => Ok(json!(text)),
        Kind::Bool => match text {
            "yes" => Ok(json!(true)),
            "no" => Ok(json!(false)),
            other => Err(format!(
                "expected yes or no, got `{}`",
                crate::logging::sanitize(other, 32)
            )),
        },
        Kind::Int => text.parse::<i64>().map(|n| json!(n)).map_err(|_| {
            format!(
                "expected a whole number, got `{}`",
                crate::logging::sanitize(text, 32)
            )
        }),
        Kind::List => {
            let items: Vec<&str> = text
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if items.is_empty() {
                Err("no entries".into())
            } else {
                Ok(json!(items))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Debian 13 host (OpenSSH 10.0p1) with the stock configuration, as `sshd -T` prints it: every
    /// keyword, including the many this reader ignores.
    const STOCK: &[u8] = include_bytes!("../../tests/fixtures/facts/debian13/sshd-T.stock");
    /// The same host after an operator set `PermitRootLogin no`, `PasswordAuthentication no`,
    /// `MaxAuthTries 3`, `Ciphers`, and an `X11Forwarding no` drop-in (AC-2.1).
    const HARDENED: &[u8] = include_bytes!("../../tests/fixtures/facts/debian13/sshd-T.hardened");

    fn ok(outcomes: &HashMap<&'static str, Outcome>, key: &str) -> Value {
        match &outcomes[key] {
            Outcome::Ok(value) => value.clone(),
            other => panic!("{key}: {other:?}"),
        }
    }

    #[test]
    fn stock_debian_13_values() {
        let facts = convert(STOCK);
        assert_eq!(facts.len(), FACTS.len());
        assert_eq!(
            ok(&facts, "sshd.permitrootlogin"),
            json!("prohibit-password")
        );
        assert_eq!(ok(&facts, "sshd.passwordauthentication"), json!(true));
        assert_eq!(ok(&facts, "sshd.permitemptypasswords"), json!(false));
        assert_eq!(ok(&facts, "sshd.pubkeyauthentication"), json!(true));
        assert_eq!(ok(&facts, "sshd.hostbasedauthentication"), json!(false));
        assert_eq!(ok(&facts, "sshd.ignorerhosts"), json!(true));
        assert_eq!(ok(&facts, "sshd.permituserenvironment"), json!(false));
        assert_eq!(ok(&facts, "sshd.x11forwarding"), json!(true));
        assert_eq!(ok(&facts, "sshd.usepam"), json!(true));
        assert_eq!(ok(&facts, "sshd.allowtcpforwarding"), json!("yes"));
        assert_eq!(ok(&facts, "sshd.loglevel"), json!("INFO"));
        assert_eq!(ok(&facts, "sshd.maxauthtries"), json!(6));
        assert_eq!(ok(&facts, "sshd.maxsessions"), json!(10));
        assert_eq!(ok(&facts, "sshd.logingracetime"), json!(120));
        assert_eq!(ok(&facts, "sshd.clientaliveinterval"), json!(0));
        assert_eq!(ok(&facts, "sshd.clientalivecountmax"), json!(3));
        assert_eq!(ok(&facts, "sshd.banner"), json!("none"));
        let ciphers = ok(&facts, "sshd.ciphers");
        assert_eq!(ciphers[0], json!("chacha20-poly1305@openssh.com"));
        assert_eq!(ciphers.as_array().unwrap().len(), 6);
        assert_eq!(
            ok(&facts, "sshd.kexalgorithms")[0],
            json!("mlkem768x25519-sha256")
        );
        assert_eq!(ok(&facts, "sshd.macs")[0], json!("umac-64-etm@openssh.com"));
    }

    #[test]
    fn a_changed_permitrootlogin_changes_the_reported_value() {
        // AC-2.1: the same fixture host before and after the operator's change.
        let before = convert(STOCK);
        let after = convert(HARDENED);
        assert_eq!(
            ok(&before, "sshd.permitrootlogin"),
            json!("prohibit-password")
        );
        assert_eq!(ok(&after, "sshd.permitrootlogin"), json!("no"));
        assert_eq!(ok(&after, "sshd.passwordauthentication"), json!(false));
        assert_eq!(ok(&after, "sshd.maxauthtries"), json!(3));
        assert_eq!(ok(&after, "sshd.x11forwarding"), json!(false));
        assert_eq!(
            ok(&after, "sshd.ciphers"),
            json!(["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"]),
            "the order sshd prints is kept"
        );
    }

    #[test]
    fn only_the_listed_keywords_are_kept_and_no_key_material_is_read() {
        // The fixture prints `hostkey` and `authorizedkeysfile` lines; nothing of them is in a fact.
        let facts = convert(STOCK);
        let everything = format!("{facts:?}");
        assert!(!everything.contains("ssh_host_"), "{everything}");
        assert!(!everything.contains("authorized_keys"), "{everything}");
        assert!(STOCK.windows(8).any(|w| w == b"hostkey "));
    }

    #[test]
    fn the_old_spelling_of_prohibit_password_is_normalised() {
        let facts = convert(b"permitrootlogin without-password\n");
        assert_eq!(
            ok(&facts, "sshd.permitrootlogin"),
            json!("prohibit-password")
        );
    }

    #[test]
    fn a_missing_keyword_makes_only_that_fact_unreadable() {
        let facts = convert(b"permitrootlogin no\nmaxauthtries 4\n");
        assert_eq!(ok(&facts, "sshd.permitrootlogin"), json!("no"));
        assert_eq!(ok(&facts, "sshd.maxauthtries"), json!(4));
        assert_eq!(
            facts["sshd.x11forwarding"],
            Outcome::Unreadable("sshd -T did not print `x11forwarding`".into())
        );
    }

    #[test]
    fn an_unexpected_value_is_unreadable_not_guessed() {
        let facts = convert(
            b"permitrootlogin maybe\nusepam sometimes\nmaxauthtries many\nciphers ,\nbanner\n",
        );
        for key in [
            "sshd.permitrootlogin",
            "sshd.usepam",
            "sshd.maxauthtries",
            "sshd.ciphers",
            "sshd.banner",
        ] {
            assert!(matches!(facts[key], Outcome::Unreadable(_)), "{key}");
        }
    }

    #[test]
    fn a_scalar_printed_twice_is_unreadable() {
        let facts = convert(b"loglevel INFO\nloglevel DEBUG\n");
        match &facts["sshd.loglevel"] {
            Outcome::Unreadable(reason) => assert!(reason.contains("more than once"), "{reason}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn output_that_is_not_text_makes_every_fact_unreadable() {
        for output in [&b""[..], &b"\xff\xfe\x00"[..], &b"  \n\n"[..]] {
            let facts = convert(output);
            assert_eq!(facts.len(), FACTS.len());
            assert!(facts.values().all(|o| matches!(o, Outcome::Unreadable(_))));
        }
    }

    #[test]
    fn keywords_are_matched_in_any_case() {
        let facts = convert(b"PermitRootLogin yes\n");
        assert_eq!(ok(&facts, "sshd.permitrootlogin"), json!("yes"));
    }
}
