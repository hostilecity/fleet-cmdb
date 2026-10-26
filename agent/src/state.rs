//! Persistent agent state under `/var/lib/fleet-agent` (FR-1.6, DEC-03).
//!
//! Holds small records such as the last boot identifier and the last reported stable facts (and, in
//! Phase 3, task records). Writes are atomic. Losing the directory must never break enrollment: missing
//! or corrupt state is treated as empty. Implemented in P1-AGENT-CORE and P1-AGENT-REPORT.
