//! Structured logging to the systemd journal (FR-1.6, NFR-4).
//!
//! One timestamped line per event on stdout, which systemd sends to the journal, with the event's
//! fields as `key=value` pairs, for example:
//!
//! ```text
//! 2026-01-01T12:00:00.000000Z  WARN cannot reach the server; will retry status=0 retry_in_seconds=7
//! ```
//!
//! The credential is never logged: the only type that holds it, [`crate::config::Credential`],
//! redacts itself in `Debug` and `Display`. Log lines carry the credential's non-secret key id where
//! the host's identity is useful. Messages from dependencies (`log` crate records from the HTTP
//! client) are not bridged in, so they cannot print request headers.

use tracing::Subscriber;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::fmt::MakeWriter;

use crate::config::LogLevel;

fn level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Trace => LevelFilter::TRACE,
    }
}

/// The agent's log format, writing to `writer`. Tests use it with an in-memory writer to see exactly
/// what the agent would log.
pub fn subscriber<W>(level: LogLevel, writer: W) -> impl Subscriber + Send + Sync
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .with_max_level(level_filter(level))
        .with_target(false)
        .with_writer(writer)
        .finish()
}

/// Installs the agent's logger on stdout for the rest of the process.
pub fn init(level: LogLevel) {
    // Fails only if a logger is already installed, in which case that one keeps working.
    let _ = tracing::subscriber::set_global_default(subscriber(level, std::io::stdout));
}

/// Makes `text` from the server safe to put in one log line: control characters (including newlines,
/// which could forge extra journal lines) become spaces, and the length is bounded.
pub fn sanitize(text: &str, max_chars: usize) -> String {
    text.chars()
        .take(max_chars)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// An in-memory log writer for tests.
#[cfg(test)]
pub(crate) mod capture {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    use crate::config::LogLevel;

    #[derive(Clone, Default)]
    pub struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Captured {
        pub fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Runs `f` with the agent's log format (at `trace`, so nothing is filtered out) and returns
    /// what it logged.
    pub fn logs_of<T>(f: impl FnOnce() -> T) -> (T, String) {
        let captured = Captured::default();
        let subscriber = super::subscriber(LogLevel::Trace, captured.clone());
        let result = tracing::subscriber::with_default(subscriber, f);
        (result, captured.text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, tests as cfg};

    #[test]
    fn lines_are_timestamped_with_fields() {
        let ((), text) = capture::logs_of(|| tracing::info!(report_id = "r-1", "sent"));
        let line = text.lines().next().unwrap();
        // RFC 3339 UTC timestamp first, for example 2026-01-01T12:00:00.000000Z.
        assert!(
            line.as_bytes()[4] == b'-' && line.contains('T') && line.contains("Z "),
            "{line}"
        );
        assert!(
            line.contains("INFO") && line.contains("sent") && line.contains("report_id=\"r-1\"")
        );
    }

    #[test]
    fn logging_the_config_never_logs_the_credential() {
        let config = Config::from_toml(&cfg::minimal()).unwrap();
        let ((), text) = capture::logs_of(|| {
            tracing::info!(?config, credential = %config.credential, "loaded");
            tracing::debug!("config: {config:?}");
        });
        assert!(text.contains("loaded"));
        assert!(!text.contains(cfg::SECRET), "credential leaked: {text}");
    }

    #[test]
    fn level_filter_applies() {
        let captured = capture::Captured::default();
        let subscriber = subscriber(LogLevel::Warn, captured.clone());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("hidden");
            tracing::warn!("shown");
        });
        let text = captured.text();
        assert!(text.contains("shown") && !text.contains("hidden"));
    }

    #[test]
    fn sanitize_removes_newlines_and_bounds_length() {
        assert_eq!(sanitize("a\nb\r\x1b[31mc", 100), "a b  [31mc");
        assert_eq!(sanitize("abcdef", 3), "abc");
    }
}
