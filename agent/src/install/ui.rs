//! What the installer prints (P1-A10): plain, ordered, copy-pasteable lines for a person, nothing but
//! errors and the approval details with `--quiet`, and one JSON object per line with `--json`.
//!
//! There is no colour or cursor movement. On a terminal the approval countdown rewrites its own line
//! with a carriage return; elsewhere it prints a line a minute. Nothing printed here ever contains the
//! credential, an enrollment token, or a device code: those types redact themselves, and the code that
//! calls this module never passes them.

use std::io::Write;
use std::time::Duration;

use serde_json::{Value, json};

use super::{Failure, InstallError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Human,
    Quiet,
    Json,
}

pub struct Ui {
    mode: Mode,
    /// Whether stdout is a terminal: enables the QR code and the self-rewriting countdown.
    tty: bool,
    out: Box<dyn Write>,
    err: Box<dyn Write>,
    /// A countdown line is on screen and must be ended before anything else is printed.
    countdown_open: bool,
    last_countdown_minute: Option<u64>,
    /// Something was printed, so an error is set off from it by a blank line.
    printed: bool,
}

/// Indentation for the lines under a step heading.
const PAD: &str = "      ";

impl Ui {
    pub fn new(mode: Mode, tty: bool, out: Box<dyn Write>, err: Box<dyn Write>) -> Self {
        Self {
            mode,
            tty,
            out,
            err,
            countdown_open: false,
            last_countdown_minute: None,
            printed: false,
        }
    }

    fn json(&mut self, value: Value) {
        let _ = writeln!(self.out, "{value}");
        let _ = self.out.flush();
    }

    fn line(&mut self, text: &str) {
        self.end_countdown();
        self.printed = true;
        let _ = writeln!(self.out, "{text}");
        let _ = self.out.flush();
    }

    fn end_countdown(&mut self) {
        if self.countdown_open {
            let _ = writeln!(self.out);
            self.countdown_open = false;
        }
    }

    /// The first line: which command and version.
    pub fn title(&mut self, text: &str) {
        if self.mode == Mode::Human {
            self.line(text);
            self.line("");
        }
    }

    /// A numbered step heading, for example `[1/4] Checking this VM`.
    pub fn step(&mut self, number: u32, total: u32, title: &str) {
        match self.mode {
            Mode::Human => self.line(&format!("[{number}/{total}] {title}")),
            Mode::Json => {
                self.json(json!({"event": "step", "step": number, "of": total, "title": title}))
            }
            Mode::Quiet => {}
        }
    }

    /// A line of detail under the current step.
    pub fn detail(&mut self, text: &str) {
        match self.mode {
            Mode::Human => self.line(&format!("{PAD}{text}")),
            Mode::Json => self.json(json!({"event": "detail", "message": text})),
            Mode::Quiet => {}
        }
    }

    /// A warning a person should read even with `--quiet` (to stderr).
    pub fn warn(&mut self, text: &str) {
        match self.mode {
            Mode::Json => self.json(json!({"event": "warning", "message": text})),
            Mode::Human | Mode::Quiet => {
                self.end_countdown();
                let _ = writeln!(self.err, "fleet-agent: warning: {text}");
            }
        }
    }

    /// Where and how to approve the onboarding request. Shown in every mode: someone must act on it.
    pub fn approval(&mut self, page: &str, user_code: &str, expires: Duration, qr: Option<String>) {
        let minutes = match expires.as_secs().div_ceil(60) {
            1 => "1 minute".to_owned(),
            n => format!("{n} minutes"),
        };
        match self.mode {
            Mode::Json => self.json(json!({
                "event": "approval_required",
                "verification_uri_complete": page,
                "user_code": user_code,
                "expires_in": expires.as_secs(),
            })),
            Mode::Quiet => {
                self.line(&format!(
                    "Approve this VM at {page} (code {user_code}) within {minutes}."
                ));
            }
            Mode::Human => {
                self.line(&format!("{PAD}An operator must approve this VM in the dashboard. Open this page, signed in:"));
                self.line("");
                self.line(&format!("{PAD}    {page}"));
                self.line("");
                self.line(&format!("{PAD}and check that it shows this code:"));
                self.line("");
                self.line(&format!("{PAD}    {user_code}"));
                self.line("");
                if let Some(qr) = qr.filter(|_| self.tty) {
                    self.line(&format!("{PAD}Or scan this QR code of the page:"));
                    for row in qr.lines() {
                        self.line(&format!("{PAD}{row}"));
                    }
                    self.line("");
                }
                self.line(&format!(
                    "{PAD}The request expires in {minutes}. Press Ctrl-C to cancel; nothing is enrolled until it is approved."
                ));
            }
        }
    }

    /// The time left for approval. On a terminal the line rewrites itself; elsewhere a line a minute.
    pub fn countdown(&mut self, left: Duration) {
        if self.mode != Mode::Human {
            return;
        }
        let secs = left.as_secs();
        if self.tty {
            let _ = write!(
                self.out,
                "\r{PAD}Waiting for approval: {}:{:02} left   ",
                secs / 60,
                secs % 60
            );
            let _ = self.out.flush();
            self.countdown_open = true;
        } else {
            let minute = secs.div_ceil(60);
            if self.last_countdown_minute != Some(minute) {
                self.last_countdown_minute = Some(minute);
                self.line(&format!("{PAD}Waiting for approval ({minute} min left)"));
            }
        }
    }

    /// The final summary, as label/value pairs.
    pub fn summary(&mut self, headline: &str, event: &str, rows: &[(&str, String)], extra: Value) {
        match self.mode {
            Mode::Human => {
                self.line("");
                self.line(headline);
                let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0) + 1;
                for (key, value) in rows {
                    self.line(&format!("  {:<width$} {value}", format!("{key}:")));
                }
            }
            Mode::Json => {
                let mut object = json!({"event": event, "message": headline});
                for (key, value) in rows {
                    object[key.to_ascii_lowercase().replace(' ', "_")] = json!(value);
                }
                if let (Some(object), Value::Object(extra)) = (object.as_object_mut(), extra) {
                    object.extend(extra);
                }
                self.json(object);
            }
            Mode::Quiet => {}
        }
    }

    /// A failure: what happened and what to do next. Human and quiet output go to stderr.
    pub fn error(&mut self, error: &InstallError) {
        match self.mode {
            Mode::Json => self.json(json!({
                "event": "error",
                "error": error.failure.kind(),
                "exit_code": error.failure.code(),
                "message": error.what,
                "next_step": error.next,
            })),
            Mode::Human | Mode::Quiet => {
                self.end_countdown();
                if self.printed {
                    let _ = writeln!(self.err);
                }
                let _ = writeln!(self.err, "fleet-agent: {}", error.what);
                if !error.next.is_empty() {
                    let _ = writeln!(self.err, "Next: {}", error.next);
                }
                if error.failure != Failure::Usage {
                    let _ = writeln!(self.err, "(exit code {})", error.failure.code());
                }
                let _ = self.err.flush();
            }
        }
    }
}

/// A shared in-memory writer, so tests can read what the installer printed.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

#[cfg(test)]
impl Captured {
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

#[cfg(test)]
impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
