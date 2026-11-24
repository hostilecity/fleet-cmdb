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
  # A confirmed stage opens in RolloutAdvanceJob (#199). Specs run that job as soon as it is enqueued, as a worker
  # would, unless tagged rollout_jobs: :enqueued to look at it before it runs.
  config.around do |example|
    adapter = ActiveJob::Base.queue_adapter
    next example.run if example.metadata[:rollout_jobs] == :enqueued || !adapter.is_a?(ActiveJob::QueueAdapters::TestAdapter)

    saved = [ adapter.perform_enqueued_jobs, adapter.filter ]
    adapter.perform_enqueued_jobs = true
    adapter.filter = [ RolloutAdvanceJob ]
    example.run
  ensure
    adapter.perform_enqueued_jobs, adapter.filter = saved if saved
  end
  # One-second spread, whatever the stage's size: every offer time is the opening time, so directives are due at once.
  config.around do |example|
    rollouts = Rails.configuration.x.rollouts
    saved = rollouts.to_h.slice(:spread, :confirmation_timeout, :downloads_per_second, :large_fleet_hosts)
    rollouts.spread = 1
    rollouts.downloads_per_second = 1_000_000
    example.run
  ensure
    saved.each { |key, value| rollouts.public_send(:"#{key}=", value) }
  end
  # The restart-loop settings (#251), as a spec may change them.
  config.around do |example|
    restart_loop = Rails.configuration.x.restart_loop
    saved = restart_loop.to_h.slice(:limit, :window)
    example.run
  ensure
    saved.each { |key, value| restart_loop.public_send(:"#{key}=", value) }
  end
end
