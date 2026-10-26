//! HTTPS client for the agent API (`/api/v1`, DEC-08).
//!
//! Sends `Authorization: Bearer <credential>` and the agent version on every request, over `rustls`
//! (no OpenSSL), trusting the system roots plus the optional CA bundle from [`crate::config`].
//! Maps the API error shape, `426 agent_version_unsupported`, `429 Retry-After`, and `413` to typed
//! errors. Also performs enrollment. Implemented in P1-AGENT-CORE.
