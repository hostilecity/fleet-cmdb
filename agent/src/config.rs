//! Agent configuration (FR-1.6).
//!
//! Loads the TOML config file (root-owned, mode `0600`, DEC-03): server URL, credential, heartbeat and
//! inventory intervals, log level, and an optional path to an extra certificate authority bundle.
//! There is deliberately no setting to disable certificate verification. Implemented in P1-AGENT-CORE.
