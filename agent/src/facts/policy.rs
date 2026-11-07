//! Login and password policy (P2-A02): `login_defs.*`, `useradd.inactive`, and `pwquality.*`, from the
//! configuration files that set them. Nothing here runs a command or reads a password hash.
//!
//! # `login_defs.*`: `/etc/login.defs`
//!
//! Lines are `NAME value`; `#` starts a comment line; a later line for a name replaces an earlier one
//! (as shadow's own reader does); a value in matching quotes loses them. `PASS_MAX_DAYS`,
//! `PASS_MIN_DAYS`, and `PASS_WARN_AGE` are whole numbers, read as shadow reads them (`0x` is
//! hexadecimal, a leading `0` octal). `UMASK` and `ENCRYPT_METHOD` are reported as written. A name the
//! file does not set is `unreadable` with the reason "not set" rather than a guessed default: a rule
//! about it should see that the host states nothing, not a value somebody assumed.
//!
//! # `useradd.inactive`: `/etc/default/useradd`
//!
//! Shell-style `INACTIVE=30`, the last assignment wins. When the file does not exist, or does not set
//! `INACTIVE`, `useradd` uses its built-in default of `-1` (never lock an expired account), and that is
//! the reported value: it is what the host will do.
//!
//! # `pwquality.*`: libpwquality
//!
//! `minlen`, `minclass`, `maxrepeat`, `dcredit`, `ucredit`, `lcredit`, and `ocredit` are resolved as the
//! module resolves them: the `*.conf` files of `/etc/security/pwquality.conf.d/` in name order, then
//! `/etc/security/pwquality.conf` (a later file wins, so the main file overrides every drop-in, as
//! pwquality.conf(5) says), then options on the `pam_pwquality.so` line of
//! `/etc/pam.d/common-password` (which win over both). `retry` is a PAM
//! option only, so it comes from that line alone. A setting nobody sets is `unreadable` ("not set":
//! the module's built-in default applies), for the reason given above. When there is no
//! `pwquality.conf`, no drop-in, and no `pam_pwquality.so` line, every `pwquality.*` fact is
//! `unreadable` with "pwquality is not set up on this host". A `conf=` option on the PAM line points
//! the module at another file this agent does not follow, so every `pwquality.*` fact is `unreadable`
//! with that reason. These facts describe the configuration; they do not prove the module is
//! enforced for every service.
//!
//! The parsers are pure functions over file contents.

use std::collections::HashMap;

use serde_json::json;

use super::manifest::FactType;
use super::{Ctx, Outcome, io_reason};

const LOGIN_DEFS: &str = "/etc/login.defs";
const USERADD: &str = "/etc/default/useradd";
const PWQUALITY_CONF: &str = "/etc/security/pwquality.conf";
const PWQUALITY_DIR: &str = "/etc/security/pwquality.conf.d";
const PAM_PASSWORD: &str = "/etc/pam.d/common-password";
const MAX_FILE: u64 = 256 * 1024;
const MAX_DROPINS: usize = 64;

// --- login.defs --------------------------------------------------------------------------------

/// `login_defs.*` facts: the key, the `login.defs` name, and the type.
const LOGIN_DEFS_FACTS: &[(&str, &str, FactType)] = &[
    (
        "login_defs.pass_max_days",
        "PASS_MAX_DAYS",
        FactType::Integer,
    ),
    (
        "login_defs.pass_min_days",
        "PASS_MIN_DAYS",
        FactType::Integer,
    ),
    (
        "login_defs.pass_warn_age",
        "PASS_WARN_AGE",
        FactType::Integer,
    ),
    ("login_defs.umask", "UMASK", FactType::String),
    (
        "login_defs.encrypt_method",
        "ENCRYPT_METHOD",
        FactType::String,
    ),
];

pub fn login_defs_keys() -> impl Iterator<Item = (&'static str, FactType)> {
    LOGIN_DEFS_FACTS
        .iter()
        .map(|(key, _, ty)| (*key, ty.clone()))
}

pub fn read_login_defs(ctx: &Ctx) -> HashMap<&'static str, Outcome> {
    match ctx.read(LOGIN_DEFS, MAX_FILE) {
        Ok(bytes) => login_defs_facts(&bytes),
        Err(e) => fail_all(login_defs_keys().map(|(k, _)| k), io_reason(LOGIN_DEFS, &e)),
    }
}

pub fn login_defs_facts(bytes: &[u8]) -> HashMap<&'static str, Outcome> {
    let settings = match parse_login_defs(bytes) {
        Ok(settings) => settings,
        Err(problem) => {
            return fail_all(
                login_defs_keys().map(|(k, _)| k),
                format!("cannot read {LOGIN_DEFS}: {problem}"),
            );
        }
    };
    LOGIN_DEFS_FACTS
        .iter()
        .map(|(key, name, ty)| {
            let outcome = match settings.get(*name) {
                None => Outcome::Unreadable(format!("{name} is not set in {LOGIN_DEFS}")),
                Some(value) if *ty == FactType::Integer => match parse_c_integer(value) {
                    Some(n) => Outcome::Ok(json!(n)),
                    None => Outcome::Unreadable(format!(
                        "{name} in {LOGIN_DEFS} is `{}`, not a whole number",
                        crate::logging::sanitize(value, 32)
                    )),
                },
                Some(value) if value.is_empty() => {
                    Outcome::Unreadable(format!("{name} in {LOGIN_DEFS} has no value"))
                }
                Some(value) => Outcome::Ok(json!(value)),
            };
            (*key, outcome)
        })
        .collect()
}

/// `NAME value` lines to a map; the last line for a name wins.
pub fn parse_login_defs(bytes: &[u8]) -> Result<HashMap<String, String>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "the file is not valid UTF-8")?;
    let mut settings = HashMap::new();
    for line in text.lines() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = match line.split_once(char::is_whitespace) {
            Some((name, value)) => (name, value.trim()),
            None => (line, ""),
        };
        settings.insert(name.to_owned(), unquote(value).to_owned());
    }
    Ok(settings)
}

/// A whole number as C's `strtol(value, _, 0)` reads it, as shadow's `getlong` does: an optional sign,
/// then `0x` hexadecimal, a leading `0` octal, or decimal. The whole text must be consumed.
pub fn parse_c_integer(text: &str) -> Option<i64> {
    let text = text.trim();
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let (radix, digits) = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (16, hex)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, &digits[1..])
    } else {
        (10, digits)
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let magnitude = i64::from_str_radix(digits, radix).ok()?;
    Some(if negative { -magnitude } else { magnitude })
}

/// Removes one pair of matching quotes around a value.
fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 && matches!(bytes[0], b'"' | b'\'') && bytes[bytes.len() - 1] == bytes[0] {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

// --- useradd -------------------------------------------------------------------------------------

pub fn useradd_keys() -> impl Iterator<Item = (&'static str, FactType)> {
    std::iter::once(("useradd.inactive", FactType::Integer))
}

pub fn read_useradd(ctx: &Ctx) -> HashMap<&'static str, Outcome> {
    let outcome = match ctx.read(USERADD, MAX_FILE) {
        Ok(bytes) => useradd_inactive(&bytes),
        // No file: useradd's built-in default.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Outcome::Ok(json!(-1)),
        Err(e) => Outcome::Unreadable(io_reason(USERADD, &e)),
    };
    HashMap::from([("useradd.inactive", outcome)])
}

pub fn useradd_inactive(bytes: &[u8]) -> Outcome {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Outcome::Unreadable(format!(
            "cannot read {USERADD}: the file is not valid UTF-8"
        ));
    };
    let mut value: Option<&str> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("INACTIVE")
            && let Some(rest) = rest.trim_start().strip_prefix('=')
        {
            value = Some(unquote(rest.trim()));
        }
    }
    match value {
        None => Outcome::Ok(json!(-1)),
        Some(text) => match parse_c_integer(text) {
            Some(n) => Outcome::Ok(json!(n)),
            None => Outcome::Unreadable(format!(
                "INACTIVE in {USERADD} is `{}`, not a whole number",
                crate::logging::sanitize(text, 32)
            )),
        },
    }
}

// --- pwquality -----------------------------------------------------------------------------------

const PWQUALITY_KEYS: &[&str] = &[
    "pwquality.minlen",
    "pwquality.minclass",
    "pwquality.maxrepeat",
    "pwquality.retry",
    "pwquality.dcredit",
    "pwquality.ucredit",
    "pwquality.lcredit",
    "pwquality.ocredit",
];

pub fn pwquality_keys() -> impl Iterator<Item = (&'static str, FactType)> {
    PWQUALITY_KEYS.iter().map(|k| (*k, FactType::Integer))
}

pub fn read_pwquality(ctx: &Ctx) -> HashMap<&'static str, Outcome> {
    let fail = |reason: String| fail_all(PWQUALITY_KEYS.iter().copied(), reason);
    let mut texts: Vec<Vec<u8>> = Vec::new();
    let mut found_conf = false;
    // libpwquality reads the drop-ins first, then the main file, and a later setting overrides an
    // earlier one, so the main file wins over every drop-in (review of #114; pwquality.conf(5)).
    match ctx.list(PWQUALITY_DIR, MAX_DROPINS) {
        Ok(names) => {
            for name in names.into_iter().filter(|n| n.ends_with(".conf")) {
                let path = format!("{PWQUALITY_DIR}/{name}");
                match ctx.read(&path, MAX_FILE) {
                    Ok(bytes) => {
                        found_conf = true;
                        texts.push(bytes);
                    }
                    Err(e) => return fail(io_reason(&path, &e)),
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return fail(io_reason(PWQUALITY_DIR, &e)),
    }
    match ctx.read(PWQUALITY_CONF, MAX_FILE) {
        Ok(bytes) => {
            found_conf = true;
            texts.push(bytes);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return fail(io_reason(PWQUALITY_CONF, &e)),
    }
    let pam = match ctx.read(PAM_PASSWORD, MAX_FILE) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return fail(io_reason(PAM_PASSWORD, &e)),
    };
    let refs: Vec<&[u8]> = texts.iter().map(Vec::as_slice).collect();
    pwquality_facts(&refs, found_conf, pam.as_deref())
}

/// The `pwquality.*` facts from the contents of the configuration files in the order they are read
/// (`found_conf` says whether any exists) and of the PAM password file, if there is one.
pub fn pwquality_facts(
    conf_files: &[&[u8]],
    found_conf: bool,
    pam: Option<&[u8]>,
) -> HashMap<&'static str, Outcome> {
    let fail = |reason: String| fail_all(PWQUALITY_KEYS.iter().copied(), reason);
    let mut settings: HashMap<String, String> = HashMap::new();
    for file in conf_files {
        match parse_pwquality_conf(file) {
            Ok(parsed) => settings.extend(parsed),
            Err(problem) => {
                return fail(format!(
                    "cannot read the pwquality configuration: {problem}"
                ));
            }
        }
    }
    let line = match pam.map(parse_pam_pwquality).transpose() {
        Ok(line) => line.flatten(),
        Err(problem) => return fail(format!("cannot read {PAM_PASSWORD}: {problem}")),
    };
    if !found_conf && line.is_none() {
        return fail(format!(
            "pwquality is not set up on this host: there is no {PWQUALITY_CONF}, no drop-in in {PWQUALITY_DIR}, and no pam_pwquality.so line in {PAM_PASSWORD}"
        ));
    }
    let options = line.unwrap_or_default();
    if options.contains_key("conf") {
        return fail(format!(
            "pam_pwquality in {PAM_PASSWORD} is given a conf= file, which this agent does not follow"
        ));
    }
    PWQUALITY_KEYS
        .iter()
        .map(|key| {
            let name = key.strip_prefix("pwquality.").unwrap_or(key);
            let (value, source) = if name == "retry" {
                (options.get(name), PAM_PASSWORD)
            } else {
                match options.get(name) {
                    Some(value) => (Some(value), PAM_PASSWORD),
                    None => (settings.get(name), "the pwquality configuration"),
                }
            };
            let outcome = match value {
                None if name == "retry" => Outcome::Unreadable(format!(
                    "retry is not set on the pam_pwquality line in {PAM_PASSWORD}; the module's built-in default applies"
                )),
                None => Outcome::Unreadable(format!(
                    "{name} is not set in the pwquality configuration or on the pam_pwquality line; the module's built-in default applies"
                )),
                Some(value) => match value.parse::<i64>() {
                    Ok(n) => Outcome::Ok(json!(n)),
                    Err(_) => Outcome::Unreadable(format!(
                        "{name} in {source} is `{}`, not a whole number",
                        crate::logging::sanitize(value, 32)
                    )),
                },
            };
            (*key, outcome)
        })
        .collect()
}

/// `name = value` lines of a pwquality configuration file; `#` starts a comment line; the last line
/// for a name wins.
pub fn parse_pwquality_conf(bytes: &[u8]) -> Result<HashMap<String, String>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "a file is not valid UTF-8")?;
    let mut settings = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, value)) = line.split_once('=') {
            settings.insert(name.trim().to_owned(), value.trim().to_owned());
        }
    }
    Ok(settings)
}

/// The `name=value` options on the `password ... pam_pwquality.so` lines of a PAM file (later lines
/// win), or `None` when no line uses the module. Options without a value (`use_authtok`,
/// `enforce_for_root`) are ignored.
pub fn parse_pam_pwquality(bytes: &[u8]) -> Result<Option<HashMap<String, String>>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "the file is not valid UTF-8")?;
    let mut found: Option<HashMap<String, String>> = None;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let tokens = pam_tokens(line);
        if tokens.len() < 3 || tokens[0] != "password" {
            continue;
        }
        let module = tokens[2].rsplit('/').next().unwrap_or("");
        if module != "pam_pwquality.so" {
            continue;
        }
        let options = found.get_or_insert_with(HashMap::new);
        for option in &tokens[3..] {
            if let Some((name, value)) = option.split_once('=') {
                options.insert(name.to_owned(), value.to_owned());
            }
        }
    }
    Ok(found)
}

/// Splits a PAM line on whitespace, keeping a `[...]` control field as one token.
fn pam_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        let mut token = String::new();
        if c == '[' {
            for c in chars.by_ref() {
                token.push(c);
                if c == ']' {
                    break;
                }
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                token.push(c);
                chars.next();
            }
        }
        tokens.push(token);
    }
    tokens
}

fn fail_all(
    keys: impl IntoIterator<Item = &'static str>,
    reason: String,
) -> HashMap<&'static str, Outcome> {
    keys.into_iter()
        .map(|key| (key, Outcome::Unreadable(reason.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const LOGIN_DEFS_FIXTURE: &[u8] =
        include_bytes!("../../tests/fixtures/facts/debian13/login.defs");
    const PWQUALITY_FIXTURE: &[u8] =
        include_bytes!("../../tests/fixtures/facts/debian13/pwquality.conf");
    const PWQUALITY_DROPIN: &[u8] =
        include_bytes!("../../tests/fixtures/facts/debian13/pwquality-dropin.conf");
    const PAM_STOCK: &[u8] = include_bytes!("../../tests/fixtures/facts/debian13/common-password");
    const PAM_HARDENED: &[u8] =
        include_bytes!("../../tests/fixtures/facts/debian13/common-password.pwquality");

    fn value(facts: &HashMap<&'static str, Outcome>, key: &str) -> Value {
        match &facts[key] {
            Outcome::Ok(v) => v.clone(),
            other => panic!("{key}: {other:?}"),
        }
    }

    fn reason(facts: &HashMap<&'static str, Outcome>, key: &str) -> String {
        match &facts[key] {
            Outcome::Unreadable(r) => r.clone(),
            other => panic!("{key}: {other:?}"),
        }
    }

    #[test]
    fn stock_debian_13_login_defs() {
        let facts = login_defs_facts(LOGIN_DEFS_FIXTURE);
        assert_eq!(value(&facts, "login_defs.pass_max_days"), json!(99999));
        assert_eq!(value(&facts, "login_defs.pass_min_days"), json!(0));
        assert_eq!(value(&facts, "login_defs.pass_warn_age"), json!(7));
        assert_eq!(value(&facts, "login_defs.umask"), json!("022"));
        assert_eq!(
            value(&facts, "login_defs.encrypt_method"),
            json!("YESCRYPT")
        );
    }

    #[test]
    fn the_last_line_wins_and_quotes_and_comments_are_handled() {
        let facts = login_defs_facts(
            b"# PASS_MAX_DAYS 1\nPASS_MAX_DAYS 99999\n  PASS_MAX_DAYS\t90  \nUMASK \"027\"\nENCRYPT_METHOD 'SHA512'\nPASS_MIN_DAYS 0x10\nPASS_WARN_AGE 010\n",
        );
        assert_eq!(value(&facts, "login_defs.pass_max_days"), json!(90));
        assert_eq!(value(&facts, "login_defs.umask"), json!("027"));
        assert_eq!(value(&facts, "login_defs.encrypt_method"), json!("SHA512"));
        assert_eq!(value(&facts, "login_defs.pass_min_days"), json!(16));
        assert_eq!(
            value(&facts, "login_defs.pass_warn_age"),
            json!(8),
            "octal, as shadow reads it"
        );
    }

    #[test]
    fn a_setting_login_defs_does_not_make_is_unreadable_not_guessed() {
        let facts = login_defs_facts(b"PASS_MAX_DAYS 60\n");
        assert_eq!(value(&facts, "login_defs.pass_max_days"), json!(60));
        assert_eq!(
            reason(&facts, "login_defs.umask"),
            "UMASK is not set in /etc/login.defs"
        );
        let facts = login_defs_facts(b"PASS_MAX_DAYS soon\nUMASK\n");
        assert!(reason(&facts, "login_defs.pass_max_days").contains("not a whole number"));
        assert!(reason(&facts, "login_defs.umask").contains("has no value"));
    }

    #[test]
    fn a_login_defs_that_is_not_text_is_unreadable() {
        let facts = login_defs_facts(b"PASS_MAX_DAYS \xff\n");
        assert_eq!(facts.len(), 5);
        assert!(reason(&facts, "login_defs.umask").contains("not valid UTF-8"));
    }

    #[test]
    fn c_integers() {
        for (text, expected) in [
            ("0", Some(0)),
            ("99999", Some(99999)),
            ("-1", Some(-1)),
            ("+5", Some(5)),
            ("0x1f", Some(31)),
            ("010", Some(8)),
            ("  7 ", Some(7)),
        ] {
            assert_eq!(parse_c_integer(text), expected, "{text:?}");
        }
        for text in ["", "-", "0x", "08", "12abc", "1 2", "1.5", "--1", "٣"] {
            assert_eq!(parse_c_integer(text), None, "{text:?}");
        }
        assert_eq!(parse_c_integer("99999999999999999999"), None);
    }

    #[test]
    fn useradd_inactive_defaults_to_never() {
        assert_eq!(
            useradd_inactive(b"# INACTIVE=-1\nSHELL=/bin/sh\n"),
            Outcome::Ok(json!(-1))
        );
        assert_eq!(useradd_inactive(b""), Outcome::Ok(json!(-1)));
        assert_eq!(useradd_inactive(b"INACTIVE=30\n"), Outcome::Ok(json!(30)));
        assert_eq!(
            useradd_inactive(b"INACTIVE=30\nINACTIVE = \"45\"\n"),
            Outcome::Ok(json!(45))
        );
        assert_eq!(useradd_inactive(b"INACTIVE_X=3\n"), Outcome::Ok(json!(-1)));
        assert!(matches!(
            useradd_inactive(b"INACTIVE=soon\n"),
            Outcome::Unreadable(_)
        ));
        assert!(matches!(useradd_inactive(b"\xff"), Outcome::Unreadable(_)));
    }

    #[test]
    fn pwquality_that_nobody_configured_is_unreadable_per_setting() {
        // The stock Debian files with libpam-pwquality installed: everything commented out, and the
        // PAM line has only `retry=3`.
        let facts = pwquality_facts(&[PWQUALITY_FIXTURE], true, Some(PAM_STOCK));
        assert_eq!(value(&facts, "pwquality.retry"), json!(3));
        for key in [
            "pwquality.minlen",
            "pwquality.minclass",
            "pwquality.dcredit",
        ] {
            assert!(reason(&facts, key).contains("is not set"), "{key}");
        }
        assert_eq!(facts.len(), 8);
    }

    #[test]
    fn pwquality_precedence_is_pam_then_the_main_file_then_the_dropins() {
        // pwquality.conf: minlen=12, minclass=3. The drop-in: minlen=14, dcredit=-1, ucredit=-1.
        // The PAM line: minlen=16 retry=5. Files are given in the order libpwquality reads them.
        let facts = pwquality_facts(
            &[PWQUALITY_DROPIN, PWQUALITY_FIXTURE],
            true,
            Some(PAM_HARDENED),
        );
        assert_eq!(
            value(&facts, "pwquality.minlen"),
            json!(16),
            "PAM option wins"
        );
        assert_eq!(value(&facts, "pwquality.retry"), json!(5));
        assert_eq!(value(&facts, "pwquality.dcredit"), json!(-1), "drop-in");
        assert_eq!(value(&facts, "pwquality.ucredit"), json!(-1));
        let main_only = pwquality_facts(&[PWQUALITY_FIXTURE_ACTIVE], true, None);
        assert_eq!(value(&main_only, "pwquality.minlen"), json!(12));
        assert_eq!(value(&main_only, "pwquality.minclass"), json!(3));
        assert!(reason(&main_only, "pwquality.retry").contains("retry is not set"));
        let drop = pwquality_facts(
            &[PWQUALITY_DROPIN, PWQUALITY_FIXTURE_ACTIVE],
            true,
            Some(PAM_STOCK),
        );
        assert_eq!(
            value(&drop, "pwquality.minlen"),
            json!(12),
            "the main file, read last, wins"
        );
        assert_eq!(
            value(&drop, "pwquality.dcredit"),
            json!(-1),
            "kept from the drop-in"
        );
    }

    #[test]
    fn the_reader_lets_the_main_pwquality_file_override_a_dropin() {
        // Review of #114: the reader merged the main file first, so a drop-in's minlen=14 was reported
        // although libpwquality applies the main file's minlen=12.
        let host = crate::facts::fake::FakeHost::debian13()
            .with_file(PWQUALITY_CONF, PWQUALITY_FIXTURE_ACTIVE)
            .with_dir(PWQUALITY_DIR, &["50-local.conf"])
            .with_file(&format!("{PWQUALITY_DIR}/50-local.conf"), PWQUALITY_DROPIN);
        let ctx = Ctx::new(&host, crate::facts::BUDGET);
        let facts = read_pwquality(&ctx);
        assert_eq!(value(&facts, "pwquality.minlen"), json!(12));
        assert_eq!(value(&facts, "pwquality.dcredit"), json!(-1));
    }

    /// The main file with `minlen = 12` and `minclass = 3` set.
    const PWQUALITY_FIXTURE_ACTIVE: &[u8] = b"# comment\nminlen = 12\nminclass=3\n";

    #[test]
    fn pwquality_that_is_not_installed_is_unreadable_with_the_reason() {
        let facts = pwquality_facts(
            &[],
            false,
            Some(b"password required pam_unix.so yescrypt\n"),
        );
        assert_eq!(facts.len(), 8);
        for key in PWQUALITY_KEYS {
            assert!(
                reason(&facts, key).contains("not set up on this host"),
                "{key}"
            );
        }
        let without_pam_file = pwquality_facts(&[], false, None);
        assert!(reason(&without_pam_file, "pwquality.minlen").contains("not set up"));
    }

    #[test]
    fn a_pam_line_alone_is_enough() {
        let facts = pwquality_facts(
            &[],
            false,
            Some(b"password requisite pam_pwquality.so retry=3 minlen=14 dcredit=-1\n"),
        );
        assert_eq!(value(&facts, "pwquality.minlen"), json!(14));
        assert_eq!(value(&facts, "pwquality.dcredit"), json!(-1));
        assert_eq!(value(&facts, "pwquality.retry"), json!(3));
    }

    #[test]
    fn a_custom_conf_file_is_not_followed() {
        let facts = pwquality_facts(
            &[PWQUALITY_FIXTURE_ACTIVE],
            true,
            Some(b"password requisite pam_pwquality.so conf=/etc/other.conf\n"),
        );
        assert!(reason(&facts, "pwquality.minlen").contains("conf="));
    }

    #[test]
    fn a_value_that_is_not_a_number_is_unreadable() {
        let facts = pwquality_facts(&[b"minlen = long\n"], true, None);
        assert!(reason(&facts, "pwquality.minlen").contains("not a whole number"));
        let facts = pwquality_facts(&[b"\xff"], true, None);
        assert!(reason(&facts, "pwquality.minlen").contains("not valid UTF-8"));
    }

    #[test]
    fn pam_lines_are_tokenised_with_bracketed_controls() {
        let pam = b"# comment\npassword\t[success=2 default=ignore]\tpam_unix.so obscure use_authtok try_first_pass yescrypt\npassword [success=1 default=ignore] /usr/lib/x86_64-linux-gnu/security/pam_pwquality.so retry=3 minlen=9 enforce_for_root # trailing\nauth required pam_pwquality.so minlen=99\n";
        let options = parse_pam_pwquality(pam).unwrap().unwrap();
        assert_eq!(options["minlen"], "9", "only `password` lines count");
        assert_eq!(options["retry"], "3");
        assert!(!options.contains_key("enforce_for_root"));
        assert_eq!(
            parse_pam_pwquality(b"password required pam_unix.so\n").unwrap(),
            None
        );
        assert_eq!(
            pam_tokens("password [a=b c=d] pam_x.so k=v"),
            ["password", "[a=b c=d]", "pam_x.so", "k=v"]
        );
    }
}
