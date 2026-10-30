//! Secrets the installer handles besides the credential: the one-time enrollment token and the
//! onboarding device code (P1-A10, NFR-1).
//!
//! Both are held in types that redact themselves in `Debug` and `Display`. The token is never taken
//! from the command line, where the process list and shell history would show it: it comes from a
//! hidden prompt (`--token`), standard input (`--token-stdin`), or `FLEET_ENROLLMENT_TOKEN`.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;

use super::{Failure, InstallError};

/// Where the enrollment token comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    /// `--token`: a hidden prompt on the terminal.
    Prompt,
    /// `--token-stdin`: one line from standard input (a hidden prompt if standard input is a terminal).
    Stdin,
    /// `FLEET_ENROLLMENT_TOKEN`.
    Env,
}

/// A one-time enrollment token. Never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    /// Checks the format from `enroll.request` (`^[A-Za-z0-9_-]{32,128}$`) after trimming surrounding
    /// whitespace. The error never repeats the input.
    pub fn parse(text: &str) -> Result<Self, InstallError> {
        let token = text.trim();
        if token.is_empty() {
            return Err(InstallError::new(
                Failure::Usage,
                "no enrollment token was given",
                "Copy the one-time token from the host's page in the dashboard and try again.",
            ));
        }
        let valid = (32..=128).contains(&token.len())
            && token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !valid {
            return Err(InstallError::new(
                Failure::Usage,
                "that is not an enrollment token (expected 32 to 128 letters, digits, '-' or '_')",
                "Copy the one-time token again from the host's page in the dashboard. If it was lost, issue a new one there (Re-enroll).",
            ));
        }
        Ok(Self(token.to_owned()))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

/// An onboarding device code: known only to this installer, never shown to a person (DEC-17).
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceCode(String);

impl DeviceCode {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DeviceCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceCode(<redacted>)")
    }
}

/// Reads the token from `source`. `env` is the value of `FLEET_ENROLLMENT_TOKEN`, read once at startup.
pub fn read(source: TokenSource, env: Option<&str>) -> Result<Token, InstallError> {
    match source {
        TokenSource::Env => Token::parse(env.unwrap_or_default()),
        TokenSource::Prompt => prompt_on_terminal(),
        TokenSource::Stdin => {
            // SAFETY: isatty only inspects the descriptor.
            if unsafe { libc::isatty(libc::STDIN_FILENO) } == 1 {
                prompt_on_terminal()
            } else {
                read_line(&mut io::stdin().lock())
            }
        }
    }
}

/// The first line of `input` (at most 4 KiB is read), as a token.
pub fn read_line(input: &mut dyn Read) -> Result<Token, InstallError> {
    let mut bytes = Vec::new();
    input
        .take(4096)
        .read_to_end(&mut bytes)
        .map_err(|e| {
            InstallError::new(
                Failure::Usage,
                format!("cannot read the enrollment token from standard input: {e}"),
                "Pipe the token in, for example from a file readable only by root: sudo fleet-agent install --server URL --token-stdin < token.txt",
            )
        })?;
    let text = String::from_utf8_lossy(&bytes);
    Token::parse(text.lines().next().unwrap_or_default())
}

/// Asks for the token on the controlling terminal with echo off. Ctrl-C or Ctrl-D cancels.
fn prompt_on_terminal() -> Result<Token, InstallError> {
    let no_terminal = |e: io::Error| {
        InstallError::new(
            Failure::Usage,
            format!("--token asks for the token on a terminal, and there is none ({e})"),
            "Without a terminal, pass the token on standard input with --token-stdin, or in the FLEET_ENROLLMENT_TOKEN environment variable.",
        )
    };
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(no_terminal)?;
    let raw = RawMode::enable(&tty).map_err(no_terminal)?;
    let _ = write!(
        tty,
        "Paste the one-time enrollment token (input is hidden) and press Enter: "
    );
    let _ = tty.flush();
    let mut text = String::new();
    let mut byte = [0u8; 1];
    let outcome = loop {
        match tty.read(&mut byte) {
            Ok(0) => break None,
            Ok(_) => match byte[0] {
                b'\r' | b'\n' => break Some(()),
                0x03 => break None,                    // Ctrl-C
                0x04 if text.is_empty() => break None, // Ctrl-D
                0x7f | 0x08 => {
                    text.pop();
                }
                0x15 => text.clear(), // Ctrl-U
                c if (c.is_ascii_graphic() || c == b' ') && text.len() < 4096 => {
                    text.push(c as char);
                }
                _ => {}
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break None,
        }
    };
    drop(raw);
    let _ = writeln!(tty);
    match outcome {
        Some(()) => Token::parse(&text),
        None => Err(InstallError::new(
            Failure::Interrupted,
            "cancelled while asking for the enrollment token; nothing was changed by enrollment",
            "Run the same command again when you have the token.",
        )),
    }
}

/// Turns off echo, line editing, and signal keys on a terminal; restores them when dropped.
struct RawMode {
    fd: i32,
    saved: libc::termios,
}

impl RawMode {
    fn enable(tty: &std::fs::File) -> io::Result<Self> {
        let fd = tty.as_raw_fd();
        // SAFETY: an all-zero termios is a valid value to be overwritten by tcgetattr.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is an open terminal for the life of `tty`; `saved` is a valid, writable termios.
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = saved;
        raw.c_lflag &= !(libc::ECHO | libc::ICANON | libc::ISIG);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        // SAFETY: as above; `raw` is a valid termios.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, saved })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // SAFETY: restores the attributes read from the same, still open, terminal.
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "EXAMPLE-enrollment-token-not-a-real-one-0001";

    #[test]
    fn a_token_is_trimmed_checked_and_never_printed() {
        let token = Token::parse(&format!("  {TOKEN}\n")).unwrap();
        assert_eq!(token.expose_secret(), TOKEN);
        assert!(!format!("{token:?}").contains(TOKEN));
        let code = DeviceCode::new("EXAMPLE-device-code-000000000000000000000000000".into());
        assert!(!format!("{code:?}").contains("EXAMPLE"));
    }

    #[test]
    fn malformed_tokens_are_refused_without_echoing_them() {
        for bad in [
            "",
            "short",
            "EXAMPLE token with spaces in it 0000000000",
            &"x".repeat(129),
        ] {
            let error = Token::parse(bad).unwrap_err();
            assert_eq!(error.failure, Failure::Usage);
            if !bad.is_empty() {
                assert!(!error.to_string().contains(bad), "{error}");
            }
        }
    }

    #[test]
    fn stdin_gives_the_first_line() {
        let token = read_line(&mut format!("{TOKEN}\nignored\n").as_bytes()).unwrap();
        assert_eq!(token.expose_secret(), TOKEN);
        assert!(read_line(&mut "".as_bytes()).is_err());
        let token = read(TokenSource::Env, Some(TOKEN)).unwrap();
        assert_eq!(token.expose_secret(), TOKEN);
        assert!(read(TokenSource::Env, Some("")).is_err());
    }
}
