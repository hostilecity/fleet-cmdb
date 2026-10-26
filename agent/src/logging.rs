//! Structured logging to the systemd journal (FR-1.6, NFR-4).
//!
//! Emits timestamped, structured lines with the host identity and report identifier so one report can
//! be traced end to end, logs each report's outcome, and never logs the credential or enrollment token.
//! Implemented in P1-AGENT-CORE.
