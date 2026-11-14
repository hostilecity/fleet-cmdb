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
  # Hosts moved per transaction by evaluate!, so a heartbeat never waits behind a fleet-wide transition.
  BATCH_SIZE = 1_000

  module_function

  # Records a heartbeat: locks the host row and re-checks the host and credential under that lock
  # (AgentHostLock, raising AgentHostLock::Refused), then reads the server clock and writes one UPDATE, plus
  # a status event only when the host was not already online. Must run inside a transaction (the
  # request's). Returns the server time it recorded. task_capabilities is the heartbeat's `tasks` object (P3-A01),
  # written to the host's capability columns in the same UPDATE (task_capability_columns).
  def record_heartbeat!(host_id:, credential_id:, agent_version:, agent_schema_version:, agent_time:, task_capabilities: nil)
    host = AgentHostLock.lock!(host_id:, credential_id:)

    # Sampled only now, after the lock: a heartbeat that waited for the row cannot write an older time than
    # the one it waited for, so last_seen_at never moves backwards.
    now = [ Time.current, host.last_seen_at ].compact.max
    updates = { last_seen_at: now, agent_version:, agent_schema_version:, agent_reported_at: agent_time, liveness_status: "online",
                **task_capability_columns(task_capabilities, now) }
    updates[:first_seen_at] = now if host.first_seen_at.nil?
    Host.where(id: host.id).update_all(updates)
    unless host.liveness_status == "online"
      HostStatusEvent.insert!({ host_id: host.id, from_status: host.liveness_status, to_status: "online", reason: "heartbeat", occurred_at: now })
    end
    # The row's "last seen" changes on every heartbeat; broadcast only status changes (P1-D05) and a new agent
    # version, such as the one an update installed (P1-D09).
    FleetBroadcast.hosts_changed([ host.id ]) unless host.liveness_status == "online" && host.agent_version == agent_version
    now
  end

  # The host columns for a heartbeat's `tasks` object (FR-3.1, P3-A01): the catalog version compiled into the agent,
  # the types it implements, the types its VM enables, and the services its VM allows restarting, which
  # Host#task_exclusion_reason reads when a task is
  # created (P3-S02). A local configuration the agent refused enables nothing, whatever the lists say. A heartbeat
  # without the object, from an agent older than Phase 3, clears them, so its host is excluded with
  # no_capability_report. Unknown fields inside the object are ignored (DEC-08).
  def task_capability_columns(tasks, now)
    if tasks.nil?
      return { task_catalog_version: nil, task_types_supported: [], task_types_enabled: [], task_services_allowed: [],
               task_capabilities_reported_at: nil }
    end

    valid = tasks["local_config"] == "valid"
    { task_catalog_version: tasks["catalog_version"], task_types_supported: tasks["supported"].sort,
      task_types_enabled: valid ? tasks["enabled"].sort : [], task_services_allowed: valid ? tasks["allowed_services"].sort : [],
      task_capabilities_reported_at: now }
  end
  private_class_method :task_capability_columns

  # Moves every active host to the status its last heartbeat implies. Runs are serialised by a session-level
  # advisory lock taken before the clock and thresholds are read and released when the run ends, so an older run
  # can never act after a newer one (review of #50); a run that finds another in progress does nothing, and the
  # next minute's run catches up. Rows a heartbeat holds are skipped and handled by the next run. Returns the
  # number of transitions written.
  #
  # Transitions are written in transactions of at most BATCH_SIZE hosts, each committed before the next, so a
  # heartbeat waits for at most one batch's row locks. In one transaction, every host going offline at once (after
  # a server outage, or a network partition) held every host row until the whole run committed: 12 s for 100,000
  # hosts on the scale benchmark, with every heartbeat of the fleet queued behind it.
  def evaluate!(now: nil, thresholds: nil)
    Host.connection_pool.with_connection do |connection|
      next 0 unless connection.select_value("SELECT pg_try_advisory_lock(#{EVALUATION_LOCK_KEY})")

      changed = []
      begin
        now ||= Time.current
        thresholds ||= Setting.liveness_thresholds
        buckets(now, thresholds).each { |status, condition| transition_all!(status, condition, now, changed) }
        changed.size
      ensure
        # Also when a later batch fails: the batches before it are committed, and open pages must show them (review of #186).
        FleetBroadcast.hosts_changed(changed)
        unlock(connection)
      end
    end
  end

  # A session lock outlives the run if it is not released, and would then block every later run on other
  # connections. If the unlock itself fails (the connection broke, or a caller's transaction was aborted), the
  # connection is closed and taken out of the pool, which releases the lock with it.
  def unlock(connection)
    connection.select_value("SELECT pg_advisory_unlock(#{EVALUATION_LOCK_KEY})")
  rescue ActiveRecord::ActiveRecordError
    connection.throw_away!
  end
  private_class_method :unlock

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

  # Every host that should move to status, in batches in id order, each batch's ids added to changed once it has
  # committed. Each batch starts after the last id of the one before, so the run reads the table once however many
  # batches it takes, and a batch smaller than BATCH_SIZE is the last.
  def transition_all!(status, condition, now, changed)
    after = 0
    loop do
      batch = transition_batch!(status, condition, now, after:)
      changed.concat(batch)
      break if batch.size < BATCH_SIZE

      after = batch.last
    end
  end
  private_class_method :transition_all!

  def transition_batch!(status, condition, now, after:)
    Host.transaction do
      candidates = Host.active.where.not(last_seen_at: nil).where(*condition).where("hosts.id > ?", after)
                       .where("hosts.liveness_status IS DISTINCT FROM ?", status)
                       .order(:id).limit(BATCH_SIZE).lock("FOR UPDATE SKIP LOCKED").pluck(:id, :liveness_status)
      next [] if candidates.empty?

      Host.where(id: candidates.map(&:first)).update_all(liveness_status: status)
      HostStatusEvent.insert_all!(candidates.map do |id, from|
        { host_id: id, from_status: from, to_status: status, reason: "evaluation", occurred_at: now }
      end)
      candidates.map(&:first)
    end
  end
  private_class_method :transition_batch!
end
