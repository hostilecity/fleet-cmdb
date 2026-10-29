//! Who the agent runs as, for the ownership checks on the config file and the state directory
//! (DEC-03, review of #65). The agent runs as root, so a file it trusts must be owned by root: a 0600
//! file owned by another user would let that user read the credential and change the server or CA.

/// The effective user id of this process (root, 0, in production).
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments, cannot fail, and has no side effects.
    unsafe { libc::geteuid() }
}

/// Whether a file or directory owned by `owner` may be trusted by a process running as `euid`.
pub fn trusted_owner(owner: u32, euid: u32) -> bool {
    owner == euid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusts_only_the_effective_user() {
        assert!(trusted_owner(0, 0));
        assert!(!trusted_owner(1000, 0));
        assert!(trusted_owner(1000, 1000));
        assert_eq!(effective_uid(), effective_uid());
    }
}
