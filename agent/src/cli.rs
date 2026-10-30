//! Command-line helpers shared by the top-level parser (`main.rs`) and the installer's (`install`).
//!
//! Arguments are split by `lexopt`, which handles `--opt value`, `--opt=value`, `--`, short-flag
//! clusters, and non-UTF-8 arguments without panicking. What this module adds is the rule for error
//! messages (review of #67): an argument is repeated only if it cannot be a secret. Every secret the
//! agent handles is at least 32 characters (enrollment tokens 32 to 128, device codes 43 to 128,
//! credentials longer still) and may start with `-`, so only short, lowercase, flag- or word-shaped
//! text is ever echoed; anything else is described, not shown.

/// What an error message may show for `arg`: the argument itself if it cannot be a secret.
pub fn shown(arg: &str) -> &str {
    if is_safe_to_show(arg) {
        arg
    } else {
        "(an argument that is not repeated here)"
    }
}

fn is_safe_to_show(arg: &str) -> bool {
    !arg.is_empty()
        && arg.len() <= 24
        && arg
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// A long option as typed, for an error message.
pub fn long(name: &str) -> String {
    shown(&format!("--{name}")).to_owned()
}

/// A short option as typed, for an error message. A token starting with `-` arrives as a run of short
/// options; at most its first character is shown.
pub fn short(c: char) -> String {
    if c.is_ascii_lowercase() {
        format!("-{c}")
    } else {
        shown("").to_owned()
    }
}

/// `lexopt`'s own messages repeat the offending argument or value; these never repeat one that could be
/// a secret (for example `--reenroll=<token>` or `--server` followed by a pasted token).
pub fn error_text(error: lexopt::Error) -> String {
    match error {
        lexopt::Error::MissingValue {
            option: Some(option),
        } => format!("{} needs a value", shown(&option)),
        lexopt::Error::MissingValue { option: None } => "an option needs a value".into(),
        lexopt::Error::UnexpectedValue { option, .. } => {
            format!("{} does not take a value", shown(&option))
        }
        lexopt::Error::UnexpectedOption(option) => {
            format!("unrecognised argument: {}", shown(&option))
        }
        lexopt::Error::UnexpectedArgument(_) => {
            format!("unrecognised argument: {}", shown(""))
        }
        lexopt::Error::NonUnicodeValue(_) => "an argument is not valid UTF-8".into(),
        _ => "the arguments cannot be read".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "-EXAMPLE-enrollment-token-not-a-real-one-0001";

    #[test]
    fn only_short_lowercase_words_and_flags_are_shown() {
        for safe in [
            "--bogus",
            "--token-stdin",
            "instal",
            "-x",
            "run",
            "--server",
        ] {
            assert_eq!(shown(safe), safe);
        }
        for secret in [
            TOKEN,
            "--example-enrollment-token-not-a-real-one",
            "EXAMPLEkey01.EXAMPLE-secret-not-a-real-credential-0001",
            "--Server",
            "",
            "abcdefghijklmnopqrstuvwxy",
        ] {
            assert_ne!(shown(secret), secret, "{secret}");
        }
        assert_eq!(short('x'), "-x");
        assert_ne!(short('E'), "-E");
        assert_eq!(long("bogus"), "--bogus");
    }

    #[test]
    fn lexopt_errors_never_repeat_a_value() {
        use lexopt::prelude::*;
        let mut parser = lexopt::Parser::from_args([format!("--quiet={TOKEN}")]);
        assert_eq!(parser.next().unwrap(), Some(Long("quiet")));
        let error = error_text(parser.next().unwrap_err());
        assert_eq!(error, "--quiet does not take a value");

        let mut parser = lexopt::Parser::from_args(["--server"]);
        parser.next().unwrap();
        assert_eq!(
            error_text(parser.value().unwrap_err()),
            "--server needs a value"
        );
    }
}
