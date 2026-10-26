//! Read-only collectors for host facts (FR-1.3).
//!
//! Gathers system, disk, and network facts for Debian 13 on x86_64 (DEC-01) and classes them as stable
//! or volatile (DEC-07). Collectors only read; they never change the host. Implemented in
//! P1-AGENT-COLLECT; Phase 2 adds configuration facts and dpkg packages.
