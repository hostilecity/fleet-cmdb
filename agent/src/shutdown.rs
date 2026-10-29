//! Graceful shutdown on `SIGTERM` and `SIGINT` (P1-A01).
//!
//! The agent's loops wait with [`Shutdown::wait`] instead of sleeping, so a stop request from
//! systemd ends the wait at once and the agent can exit cleanly between requests.

use std::io;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

/// A shared "stop requested" flag that can be waited on.
#[derive(Clone, Default)]
pub struct Shutdown(Arc<(Mutex<bool>, Condvar)>);

impl Shutdown {
    /// Requests shutdown on `SIGTERM` or `SIGINT`.
    pub fn on_signals() -> io::Result<Self> {
        let shutdown = Self::default();
        let mut signals = Signals::new([SIGTERM, SIGINT])?;
        let handle = shutdown.clone();
        thread::Builder::new()
            .name("signals".into())
            .spawn(move || {
                if let Some(signal) = signals.forever().next() {
                    let name = if signal == SIGTERM {
                        "SIGTERM"
                    } else {
                        "SIGINT"
                    };
                    tracing::info!(signal = name, "shutdown requested");
                    handle.request();
                }
            })?;
        Ok(shutdown)
    }

    /// Asks every waiter to stop.
    pub fn request(&self) {
        let (flag, condvar) = &*self.0;
        *flag.lock().unwrap_or_else(|e| e.into_inner()) = true;
        condvar.notify_all();
    }

    pub fn is_requested(&self) -> bool {
        *self.0.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Waits up to `timeout`, returning early with `true` if shutdown is requested.
    pub fn wait(&self, timeout: Duration) -> bool {
        let (flag, condvar) = &*self.0;
        let deadline = Instant::now() + timeout;
        let mut stopped = flag.lock().unwrap_or_else(|e| e.into_inner());
        while !*stopped {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            stopped = condvar
                .wait_timeout(stopped, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_times_out_without_a_request() {
        let shutdown = Shutdown::default();
        assert!(!shutdown.wait(Duration::from_millis(20)));
        assert!(!shutdown.is_requested());
    }

    #[test]
    fn request_ends_a_wait_early() {
        let shutdown = Shutdown::default();
        let other = shutdown.clone();
        let started = Instant::now();
        let waiter = thread::spawn(move || other.wait(Duration::from_secs(60)));
        thread::sleep(Duration::from_millis(20));
        shutdown.request();
        assert!(waiter.join().unwrap());
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(shutdown.wait(Duration::from_secs(60)));
    }
}
