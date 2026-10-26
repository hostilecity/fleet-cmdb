//! Heartbeat loop and report sending (FR-1.2, FR-1.3).
//!
//! Builds heartbeat and inventory payloads carrying a `report_id` (UUIDv4, reused on retry) and
//! [`crate::AGENT_SCHEMA_VERSION`], sends them on the configured intervals with backoff, and sends an
//! extra inventory report when a stable fact changes. Implemented in P1-AGENT-REPORT.
