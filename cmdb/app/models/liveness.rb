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
  # Advisory lock key that serialises evaluation runs ("live" in ASCII).
  EVALUATION_LOCK_KEY = 0x6c697665

  module_function

  # Records a heartbeat: locks the host row and re-checks the host and credential under that lock
  # (AgentHostLock, raising AgentHostLock::Refused), then reads the server clock and writes one UPDATE, plus
  # a status event only when the host was not already online. Must run inside a transaction (the
  # request's). Returns the server time it recorded.
  def record_heartbeat!(host_id:, credential_id:, agent_version:, agent_schema_version:, agent_time:)
    host = AgentHostLock.lock!(host_id:, credential_id:)

    # Sampled only now, after the lock: a heartbeat that waited for the row cannot write an older time than
    # the one it waited for, so last_seen_at never moves backwards.
    now = [ Time.current, host.last_seen_at ].compact.max
    updates = { last_seen_at: now, agent_version:, agent_schema_version:, agent_reported_at: agent_time, liveness_status: "online" }
    updates[:first_seen_at] = now if host.first_seen_at.nil?
    Host.where(id: host.id).update_all(updates)
    unless host.liveness_status == "online"
      HostStatusEvent.insert!({ host_id: host.id, from_status: host.liveness_status, to_status: "online", reason: "heartbeat", occurred_at: now })
    end
    now
  end

  # Moves every active host to the status its last heartbeat implies. Runs are serialised by a transaction-
  # level advisory lock taken before the clock and thresholds are read, so an older run can never act after
  # a newer one (review of #50); a run that finds another in progress does nothing, and the next minute's
  # run catches up. Rows a heartbeat holds are skipped and handled by the next run. Returns the number of
  # transitions written.
  def evaluate!(now: nil, thresholds: nil)
    Host.transaction do
      if Host.connection.select_value("SELECT pg_try_advisory_xact_lock(#{EVALUATION_LOCK_KEY})")
        now ||= Time.current
        thresholds ||= Setting.liveness_thresholds
        buckets(now, thresholds).sum { |status, condition| transition_all!(status, condition, now) }
      else
        0
      end
    end
  end

  def buckets(now, thresholds)
    online_after = now - thresholds[:online]
    stale_after = now - thresholds[:stale]
    {
      "online" => [ "hosts.last_seen_at > ?", online_after ],
      "stale" => [ "hosts.last_seen_at <= ? AND hosts.last_seen_at > ?", online_after, stale_after ],
      "offline" => [ "hosts.last_seen_at <= ?", stale_after ]
    }
  end
  private_class_method :buckets

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
