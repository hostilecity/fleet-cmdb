# Liveness of active hosts (FR-1.2, FR-1.4, P1-HEARTBEAT). Status is derived on the server from
# last_seen_at, which only the server clock sets; the agent's reported time is stored but never used.
#
# - A heartbeat makes the host online at once and records the transition.
# - Liveness.evaluate! (run every minute by LivenessEvaluationJob) moves active hosts between online, stale,
#   and offline by the configured thresholds. It is idempotent and safe to run concurrently.
# - Hosts that have never sent a heartbeat have no liveness status ("awaiting first contact").
# - Hosts that are not active are not evaluated; they show their enrollment state.
module Liveness
  STATUSES = %w[online stale offline].freeze

  module_function

  # Records a heartbeat for an active host: one UPDATE, plus a status event only when the host was not
  # already online. Runs inside the request transaction.
  def record_heartbeat!(host, agent_version:, agent_schema_version:, agent_time:, now: Time.current)
    previous = Host.where(id: host.id).lock.pick(:liveness_status, :first_seen_at)
    status, first_seen_at = previous
    updates = { last_seen_at: now, agent_version:, agent_schema_version:, agent_reported_at: agent_time, liveness_status: "online" }
    updates[:first_seen_at] = now if first_seen_at.nil?
    Host.where(id: host.id).update_all(updates)
    return if status == "online"

    HostStatusEvent.insert!({ host_id: host.id, from_status: status, to_status: "online", reason: "heartbeat", occurred_at: now })
  end

  # Moves every active host to the status its last heartbeat implies. Rows another transaction holds (a
  # heartbeat in flight, or a concurrent run) are skipped and handled by the next run. Returns the number
  # of transitions written.
  def evaluate!(now: Time.current, thresholds: Setting.liveness_thresholds)
    online_after = now - thresholds[:online]
    stale_after = now - thresholds[:stale]
    buckets = {
      "online" => [ "hosts.last_seen_at > ?", online_after ],
      "stale" => [ "hosts.last_seen_at <= ? AND hosts.last_seen_at > ?", online_after, stale_after ],
      "offline" => [ "hosts.last_seen_at <= ?", stale_after ]
    }
    Host.transaction do
      buckets.sum { |status, condition| transition_all!(status, condition, now) }
    end
  end

  def transition_all!(status, condition, now)
    candidates = Host.active.where.not(last_seen_at: nil).where(*condition)
                     .where("hosts.liveness_status IS DISTINCT FROM ?", status)
                     .lock("FOR UPDATE SKIP LOCKED").pluck(:id, :liveness_status)
    return 0 if candidates.empty?

    Host.where(id: candidates.map(&:first)).update_all(liveness_status: status)
    HostStatusEvent.insert_all!(candidates.map do |id, from|
      { host_id: id, from_status: from, to_status: status, reason: "evaluation", occurred_at: now }
    end)
    candidates.size
  end
  private_class_method :transition_all!
end
