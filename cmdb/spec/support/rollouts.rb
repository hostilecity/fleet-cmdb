# Helpers for rollout specs (P1-UPDATES).
module RolloutHelpers
  # An active host that last reported running the given agent version.
  def host_running(version, **attributes)
    host, credential = enrolled_host(**attributes)
    host.update_columns(agent_version: version)
    [ host, credential ]
  end

  # A release the server has imported and trusts, as an operator would have imported it.
  def release_for_rollout(version = "0.3.0")
    trust_release_keys
    import_release(signed_release(version:))
  end

  def start_rollout(release:, canaries:, operator: create(:operator), **options)
    Rollouts.start!(release:, actor: operator, canary_host_ids: canaries.map(&:id), **options)
  end

  def update_result(rollout, **overrides)
    { schema_version: 1, agent_version: "0.2.0", report_id: SecureRandom.uuid, rollout_id: rollout.id,
      version: rollout.agent_release.version, outcome: "succeeded", occurred_at: "2026-01-01T12:05:00Z" }.merge(overrides)
  end

  def audit_actions = AuditEntry.chronological.pluck(:action)
end

RSpec.configure do |config|
  config.include RolloutHelpers
  # One-second spread: every offer time is the opening time, so directives are due at once.
  config.around do |example|
    rollouts = Rails.configuration.x.rollouts
    saved = rollouts.to_h.slice(:spread, :confirmation_timeout)
    rollouts.spread = 1
    example.run
  ensure
    saved.each { |key, value| rollouts.public_send(:"#{key}=", value) }
  end
end
