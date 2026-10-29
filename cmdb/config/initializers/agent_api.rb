# Agent API settings (P1-API-AUTH). Environment files may set any of these first; tests do.
Rails.application.configure do
  api = config.x.agent_api

  # The JSON Schemas in docs/api are read at runtime, so the repository's docs/api/schemas must be present.
  # The Docker image copies them in from a named build context (see cmdb/README.md, "Docker image").
  api.schemas_dir ||= Pathname(ENV.fetch("FLEET_API_SCHEMAS_DIR") { Rails.root.join("../docs/api/schemas").to_s }).expand_path

  # Agents older than this get 426 agent_version_unsupported (FR-S.2, DEC-08).
  api.minimum_agent_version ||= ENV.fetch("FLEET_MINIMUM_AGENT_VERSION", "0.1.0")

  # Per-credential limit on authenticated endpoints, and a stricter per-address limit on enrollment.
  api.rate_limit ||= { to: Integer(ENV.fetch("FLEET_API_RATE_LIMIT_PER_MINUTE", "120")), within: 1.minute }
  api.enroll_rate_limit ||= { to: Integer(ENV.fetch("FLEET_ENROLL_RATE_LIMIT_PER_MINUTE", "10")), within: 1.minute }

  # Enrollment tokens expire after this long (DEC-04: default 24 hours).
  config.x.enrollment.token_ttl ||= Integer(ENV.fetch("FLEET_ENROLLMENT_TOKEN_TTL_HOURS", "24")).hours

  # Onboarding (DEC-17, P1-ONBOARD). The approval page lives on the dashboard; FLEET_DASHBOARD_URL overrides
  # the URL derived from FLEET_DASHBOARD_HOST (for a non-default port or scheme).
  onboarding = config.x.onboarding
  onboarding.ttl ||= Integer(ENV.fetch("FLEET_ONBOARDING_TTL_MINUTES", "10")).minutes
  onboarding.poll_interval ||= Integer(ENV.fetch("FLEET_ONBOARDING_POLL_SECONDS", "5")).seconds
  onboarding.max_open ||= Integer(ENV.fetch("FLEET_ONBOARDING_MAX_OPEN", "50"))
  onboarding.max_open_per_address ||= Integer(ENV.fetch("FLEET_ONBOARDING_MAX_OPEN_PER_ADDRESS", "5"))
  onboarding.start_rate_limit ||= { to: Integer(ENV.fetch("FLEET_ONBOARDING_RATE_LIMIT_PER_MINUTE", "10")), within: 1.minute }
  onboarding.dashboard_url ||= ENV["FLEET_DASHBOARD_URL"].presence

  config.after_initialize do
    dir = config.x.agent_api.schemas_dir
    raise "Agent API schemas not found at #{dir}; set FLEET_API_SCHEMAS_DIR" unless dir.join("v1").directory?
    raise "FLEET_MINIMUM_AGENT_VERSION is not a semantic version" unless AgentApi::AgentVersion.parse(config.x.agent_api.minimum_agent_version)
  end
end
