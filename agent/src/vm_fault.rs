//! The fault the VM test uses to make a confirmed agent crash-loop (#180, `scripts/vm-test.sh`,
//! "Crash loop on a confirmed version"). Compiled only into unit tests and into the VM test's fault
//! build (`RUSTFLAGS=--cfg fleet_vm_fault`, `scripts/update-smoke-build.sh` with `VM_FAULT=1`), never
//! into a release: `scripts/check-no-fault-hooks.sh` checks the source and the release binary
//! (threat model S7).
//!
//! With [`POISON`] in the state directory, normal mode's inventory loop panics as it starts, which stops
//! the agent with a failure every time, as a bug triggered by host state would. Recovery mode runs no
//! inventory loop, so it is unaffected; a build without the fault (the fixed release) ignores the file.

use std::path::Path;

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
}
