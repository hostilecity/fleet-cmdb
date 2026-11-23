//! The fault the VM test uses to make a confirmed agent crash-loop (#180, `scripts/vm-test.sh`,
//! "Crash loop on a confirmed version"), and the shorter lock wait its lock scenario uses (#288).
//! Compiled only into unit tests and into the VM test's fault
//! build (`RUSTFLAGS=--cfg fleet_vm_fault`, `scripts/update-smoke-build.sh` with `VM_FAULT=1`), never
//! into a release: `scripts/check-no-fault-hooks.sh` checks the source and the release binary
//! (threat model S7).
//!
//! With [`POISON`] in the state directory, normal mode's inventory loop panics as it starts, which stops
//! the agent with a failure every time, as a bug triggered by host state would. Recovery mode runs no
//! inventory loop, so it is unaffected; a build without the fault (the fixed release) ignores the file.
//!
//! With [`LOCK_WAIT_FILE`] in the default state directory when the agent starts, `apply_package_updates`
//! waits that many seconds for the package manager's locks instead of five minutes (at most the
//! default, never more), so the VM test's "Package manager lock held" scenario takes seconds. Every other
//! build has no such file check: it always waits [`crate::tasks::apply_updates::LOCK_WAIT`].

use std::path::Path;
use std::time::Duration;

/// Kept by this hook, like every fault-injection hook, so the binary checks can see it. Equal to
/// `test_support::FAULT_HOOK_MARKER` (a test checks), which the check script reads.
pub const MARKER: &str = "fleet-agent fault-injection hook: test builds only";

/// The file that switches the fault on.
pub const POISON: &str = "vm-test-poison";

/// Panics if [`POISON`] is in `state_dir`.
pub fn check(state_dir: &Path) {
    std::hint::black_box(MARKER);
    if state_dir.join(POISON).exists() {
        panic!("vm-test fault: {POISON} is in the state directory");
    }
}

/// The file that shortens the lock wait: the number of seconds, from 1 up to the default.
pub const LOCK_WAIT_FILE: &str = "vm-test-lock-wait-seconds";

/// The lock wait the agent's state directory asks for ([`LOCK_WAIT_FILE`]), or `default`.
#[cfg_attr(test, allow(dead_code))]
pub fn lock_wait(default: Duration) -> Duration {
    lock_wait_in(Path::new(crate::config::DEFAULT_STATE_DIR), default)
}

/// [`lock_wait`] for a given state directory. Anything but a whole number of seconds from 1 to
/// `default` is ignored.
pub fn lock_wait_in(state_dir: &Path, default: Duration) -> Duration {
    std::hint::black_box(MARKER);
    std::fs::read_to_string(state_dir.join(LOCK_WAIT_FILE))
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .filter(|wait| !wait.is_zero() && *wait <= default)
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_is_the_one_the_binary_check_looks_for() {
        assert_eq!(MARKER, crate::test_support::FAULT_HOOK_MARKER);
    }

    #[test]
    fn it_panics_only_with_the_poison_file() {
        let dir = crate::test_support::TempDir::new();
        check(dir.root());
        dir.write(POISON, "");
        let panicked = std::panic::catch_unwind(|| check(dir.root()));
        assert!(panicked.is_err());
    }

    #[test]
    fn the_lock_wait_is_shortened_only_by_a_valid_file() {
        let dir = crate::test_support::TempDir::new();
        let default = Duration::from_secs(300);
        assert_eq!(lock_wait_in(dir.root(), default), default);
        dir.write(LOCK_WAIT_FILE, "20\n");
        assert_eq!(lock_wait_in(dir.root(), default), Duration::from_secs(20));
        for ignored in ["0", "301", "-5", "twenty", ""] {
            dir.write(LOCK_WAIT_FILE, ignored);
            assert_eq!(lock_wait_in(dir.root(), default), default, "{ignored:?}");
        }
    }
}
