# Liveness of active hosts (FR-1.2, FR-1.4, P1-HEARTBEAT). Status is derived on the server from
# last_seen_at, which only the server clock sets; the agent's reported time is stored but never used.
#
# - A heartbeat makes the host online at once and records the transition.
# - Liveness.evaluate! (run every minute by LivenessEvaluationJob) moves active hosts between online, stale,
#   and offline by the configured thresholds. It is idempotent and safe to run concurrently.
# - Hosts that have never sent a heartbeat have no liveness status ("awaiting first contact").
# - Hosts that are not active are not evaluated; they show their enrollment state.
#
# The status and the two times are in host_liveness (HostLiveness, #192), a narrow table whose updates stay heap-only
# (HOT); a steady heartbeat does not write the hosts row. Every write of host_liveness holds the host row lock
# (AgentHostLock, or FOR NO KEY UPDATE in evaluate!), so whoever holds that lock reads the latest committed row.
module Liveness
  STATUSES = %w[online stale offline].freeze
  # Advisory lock key that serialises evaluation runs ("live" in ASCII).
  EVALUATION_LOCK_KEY = 0x6c697665
  # Hosts moved per transaction by evaluate!, so a heartbeat never waits behind a fleet-wide transition.
  BATCH_SIZE = 1_000
  # The restarts hosts.agent_recent_restarts keeps, newest first (#251): enough to count "more than N in the window"
  # exactly for any restart-loop limit up to RESTART_HISTORY - 1 (config/initializers/rollouts.rb allows 1 to 31).
  RESTART_HISTORY = 32
  # How far a process's start may be past the agent_time of the same heartbeat (one clock): more is not a value the
  # agent could have sent, and the process object is ignored (#251).
  START_SLACK = 1.second

  module_function

  # Records a heartbeat: locks the host row and re-checks the host and credential under that lock
  # (AgentHostLock, raising AgentHostLock::Refused), then writes the host's host_liveness row in one statement, plus
  # a status event only when the host was not already online. The hosts row is written only when something it holds
  # changed: the agent version or schema version, the task capabilities, the recovery-mode columns, whether recovery
  # mode is set up, or the first heartbeat's first_seen_at. Must run inside a transaction (the request's). Returns the
  # server time it recorded. task_capabilities is the heartbeat's `tasks` object (P3-A01), compared with the host's
  # capability columns (task_capability_columns); recovery is its `recovery` object (#180, ADR 0030), compared the same
  # way (recovery_columns); units is its `units` object (#232), stored as agent_recovery_coverage (recovery_coverage);
  # process is its `process` object (#251), stored by process_columns, which also counts the restarts it shows. Counted
  # restarts are passed to Rollouts.restarts_seen!, which may mark the host's rollout membership and halt the rollout:
  # only on a heartbeat that shows a restart, so a steady heartbeat reads nothing more.
  def record_heartbeat!(host_id:, credential_id:, agent_version:, agent_schema_version:, agent_time:, task_capabilities: nil,
                        recovery: nil, units: nil, process: nil)
    host = AgentHostLock.lock!(host_id:, credential_id:)

    # The clock is read only now, after the lock, and last_seen_at never moves backwards: a heartbeat that waited for
    # the row cannot write an older time than the one it waited for.
    now, was = touch(host.id, Time.current, agent_time)
    capabilities = task_capability_columns(task_capabilities)
    restarted, process_updates = process_columns(process, host, now, agent_time)
    updates = { agent_version:, agent_schema_version:, **capabilities, **recovery_columns(recovery, host, now),
                agent_recovery_coverage: recovery_coverage(units), **process_updates }
              .reject { |column, value| host[column] == value }
    if updates.keys.intersect?(capabilities.keys) || task_capabilities.nil? != host.task_capabilities_reported_at.nil?
      updates[:task_capabilities_reported_at] = task_capabilities && now
    end
    updates[:first_seen_at] = now if host.first_seen_at.nil?
    Host.where(id: host.id).update_all(updates) if updates.any?
    Rollouts.restarts_seen!(host:, recent: updates[:agent_recent_restarts], now:) if restarted.positive?
    unless was == "online"
      HostStatusEvent.insert!({ host_id: host.id, from_status: was, to_status: "online", reason: "heartbeat", occurred_at: now })
    end
    # The row's "last seen" changes on every heartbeat; broadcast only status changes (P1-D05), a new agent
    # version, such as the one an update installed (P1-D09), entering or leaving recovery mode (#180), and a change in
    # whether recovery mode is set up (#232), which the fleet list's filter and the host page show.
    # A restart too (#251): the host page shows restarts, and the fleet list's filter lists restart loops.
    unchanged = was == "online" && !updates.key?(:agent_version) && host.agent_recovery_since.nil? == recovery.nil? &&
                !updates.key?(:agent_recovery_coverage) && restarted.zero?
    FleetBroadcast.hosts_changed([ host.id ]) unless unchanged
    now
  end

  # Sets the host's host_liveness row to online at the later of now and its last_seen_at, in one statement that also
  # returns the status it had (nil before the first heartbeat, which inserts the row). Only last_seen_at,
  # agent_reported_at, and (rarely) the status change, none of them indexed, so the update is heap-only. Returns
  # [recorded time, previous status].
  def touch(host_id, now, agent_time)
    row = HostLiveness.connection.select_all(HostLiveness.sanitize_sql_array([ <<~SQL, { host_id:, now:, agent_time: } ]), "Liveness touch").cast_values.first
      WITH previous AS (SELECT host_id, liveness_status FROM host_liveness WHERE host_id = :host_id)
      UPDATE host_liveness l SET liveness_status = 'online', last_seen_at = GREATEST(l.last_seen_at, :now), agent_reported_at = :agent_time
        FROM previous p WHERE l.host_id = p.host_id
      RETURNING l.last_seen_at, p.liveness_status
    SQL
    return row if row

    HostLiveness.insert!({ host_id:, liveness_status: "online", last_seen_at: now, agent_reported_at: agent_time })
    [ now, nil ]
  end
  private_class_method :touch

  # The host columns for a heartbeat's `recovery` object (#180, ADR 0030). Absent (normal mode) clears them. Present,
  # agent_recovery_since keeps the server time of the episode's first such heartbeat, which is what makes the host
  # "recovering"; the agent's times and reason replace the last ones. The reason is agent text: stored as sent, after the
  # schema's check (one line, no control or bidirectional formatting characters, at most 256 characters), and only ever
  # shown escaped. record_heartbeat! writes only the columns that changed, so a steady recovery episode, like a steady
  # normal one, leaves the hosts row alone.
  def recovery_columns(recovery, host, now)
    if recovery.nil?
      return { agent_recovery_since: nil, agent_recovery_entered_at: nil, agent_recovery_retry_at: nil, agent_recovery_reason: nil }
    end

    { agent_recovery_since: host.agent_recovery_since || now, agent_recovery_entered_at: Time.iso8601(recovery["entered_at"]),
      agent_recovery_retry_at: Time.iso8601(recovery["retry_at"]), agent_recovery_reason: recovery["reason"] }
  end
  private_class_method :recovery_columns

  # [restarts counted, host columns] for a heartbeat's `process` object (#251). Absent (an older agent, or the
  # installer's own heartbeat), or not a value the agent could have sent (a start after the heartbeat's agent_time, an
  # exit status that does not fit its exit code; the schema has checked each value's shape and range), it changes
  # nothing: [0, {}].
  #
  # Restarts are counted from systemd's NRestarts, never from the process's start: it rises by one each time systemd
  # restarts the agent by itself, and any other start (a person, an agent update, recovery mode's hourly try, a boot)
  # sets it to 0. So against the last known value a higher one counts the difference, and a lower one counts itself (a
  # reset, then that many restarts); the first value reported, an unread one (null), or an equal one counts none, so
  # the count is a lower bound: a reset followed by exactly as many restarts as before is not seen. Each counted restart
  # is put in agent_recent_restarts at the server's time of this heartbeat, newest first, at most RESTART_HISTORY,
  # agent_restarted_at becomes that time, and agent_restart_loop_at the (limit + 1)th newest restart (nil with fewer),
  # which the fleet filter's index reads (review of #307, S1). record_heartbeat! writes only the columns that changed: a
  # process's heartbeats after its first change nothing. The agent's times are rounded to the microsecond PostgreSQL
  # keeps, so a time sent with more digits still compares equal to the stored one (review of #307, S2).
  def process_columns(process, host, now, agent_time)
    return [ 0, {} ] unless process && plausible_process?(process, agent_time)
    # A heartbeat of a process older than the one stored was held up (in a queue, behind a lock) while a newer process
    # started: what it says is out of date, and its count would read as a reset and count again restarts that were
    # counted (re-check of #307, S3). Both starts are the agent's own clock, and a process never starts before the one
    # it replaced. Ignored, as a heartbeat without the object.
    return [ 0, {} ] if host.agent_process_started_at && agent_time_of(process["started_at"]) < host.agent_process_started_at

    restarts = process["restarts"]
    known = host.agent_restarts
    counted = if restarts.nil? || known.nil? then 0
    elsif restarts > known then restarts - known
    elsif restarts < known then restarts
    else 0
    end
    stop = process["last_stop"]
    columns = { agent_process_started_at: agent_time_of(process["started_at"]), agent_restarts: restarts || known,
                agent_last_stop_result: stop&.fetch("result"), agent_last_stop_exit_code: stop&.fetch("exit_code"),
                agent_last_stop_exit_status: stop&.fetch("exit_status"), agent_last_stop_at: stop && agent_time_of(stop["stopped_at"]) }
    if counted.positive?
      recent = ([ now ] * [ counted, RESTART_HISTORY ].min + Array(host.agent_recent_restarts)).first(RESTART_HISTORY)
      columns.merge!(agent_recent_restarts: recent, agent_restarted_at: now, agent_restart_loop_at: recent[Rollouts.restart_loop.limit])
    end
    [ counted, columns ]
  end
  private_class_method :process_columns

  # An agent timestamp as PostgreSQL stores it: to the microsecond (the contract allows nine digits).
  def agent_time_of(text) = Time.iso8601(text).round(6)
  private_class_method :agent_time_of

  # Whether a schema-valid `process` object is one the agent could have sent: its start no later than the heartbeat's
  # own agent_time (the same clock), and a stop's exit status as its exit code allows (an exit status 0 to 255 for
  # exited, a signal 1 to 64 for killed or dumped, none without a code). Anything else is logged and ignored, not
  # refused: liveness must not depend on it.
  def plausible_process?(process, agent_time)
    stop = process["last_stop"]
    status = stop && stop["exit_status"]
    stop_ok = stop.nil? || exit_fits?(stop["exit_code"], status)
    return true if stop_ok && Time.iso8601(process["started_at"]) <= agent_time + START_SLACK

    Rails.logger.warn("[heartbeat] ignored a process object the agent could not have sent: #{process.to_json.truncate(300)}")
    false
  end
  private_class_method :plausible_process?

  # An exit status as systemd gives it with its exit code: none without a code, one for exited, a signal for killed or
  # dumped (or none, for a signal the agent could not number).
  def exit_fits?(code, status)
    case code
    when nil then status.nil?
    when "exited" then !status.nil?
    else status.nil? || status.between?(1, 64)
    end
  end
  private_class_method :exit_fits?

  # agent_recovery_coverage for a heartbeat's `units` object (#232): set_up, not_set_up, or unchecked (the agent could not
  # check, `recovery: null`; re-review of #235). nil without the object: not reported.
  COVERAGE = { true => "set_up", false => "not_set_up", nil => "unchecked" }.freeze

  def recovery_coverage(units) = units && COVERAGE.fetch(units["recovery"])
  private_class_method :recovery_coverage

  # The host columns for a heartbeat's `tasks` object (FR-3.1, P3-A01): the catalog version compiled into the agent,
  # the types it implements, the types its VM enables, and the services its VM allows restarting, which
  # Host#task_exclusion_reason reads when a task is created (P3-S02). A local configuration the agent refused enables
  # nothing, whatever the lists say. A heartbeat without the object, from an agent older than Phase 3, clears them, so
  # its host is excluded with no_capability_report. Unknown fields inside the object are ignored (DEC-08).
  # task_capabilities_reported_at is the time of the heartbeat that first reported them as they are now (nil without
  # the object); every later heartbeat confirms them, so the host's last_seen_at is when they were last reported.
  def task_capability_columns(tasks)
    return { task_catalog_version: nil, task_types_supported: [], task_types_enabled: [], task_services_allowed: [] } if tasks.nil?

    valid = tasks["local_config"] == "valid"
    { task_catalog_version: tasks["catalog_version"], task_types_supported: tasks["supported"].sort,
      task_types_enabled: valid ? tasks["enabled"].sort : [], task_services_allowed: valid ? tasks["allowed_services"].sort : [] }
  end
  private_class_method :task_capability_columns

  # Moves every active host to the status its last heartbeat implies. Runs are serialised by a session-level
  # advisory lock (SessionLock) taken before the clock and thresholds are read and released when the run ends, so an
  # older run can never act after a newer one (review of #50); a run that finds another in progress does nothing, and
  # the next minute's run catches up. Rows a heartbeat holds are skipped and handled by the next run. Returns the
  # number of transitions written. Behind a transaction-mode pooler the lock is on the direct connection (#198). Each
  # batch first checks the lock is still held (SessionLock), on every path: a connection reopened without a word has
  # lost it, and the run then raises SessionLock::Lost; the next minute's run catches up.
  #
  # Transitions are written in transactions of at most BATCH_SIZE hosts, each committed before the next, so a
  # heartbeat waits for at most one batch's row locks. In one transaction, every host going offline at once (after
  # a server outage, or a network partition) held every host row until the whole run committed: 12 s for 100,000
  # hosts on the scale benchmark, with every heartbeat of the fleet queued behind it.
  def evaluate!(now: nil, thresholds: nil)
    changed = []
    locked = false
    SessionLock.hold(EVALUATION_LOCK_KEY.to_s) do |still_held|
      locked = true
      now ||= Time.current
      thresholds ||= Setting.liveness_thresholds
      transition_all!(now, thresholds, changed, still_held)
    end
    changed.size
  ensure
    # After the lock is released (SessionLock), also when a later batch fails: the batches before it are committed,
    # and open pages must show them (review of #186). A failure to request is reported by LiveRefresh, never raised
    # over this run's own error.
    FleetBroadcast.hosts_changed(changed) if locked
  end

  # The status a host's last heartbeat implies, as SQL over host_liveness l.
  def target_sql(now, thresholds)
    HostLiveness.sanitize_sql_array([ "CASE WHEN l.last_seen_at > :online_after THEN 'online' WHEN l.last_seen_at > :stale_after THEN 'stale' " \
                                      "ELSE 'offline' END", { online_after: now - thresholds[:online], stale_after: now - thresholds[:stale] } ])
  end
  private_class_method :target_sql

  # Every host whose status should change, in batches in id order, each batch's ids added to changed once it has
  # committed. Each batch starts after the last id of the one before, so the run reads host_liveness, not hosts,
  # once however many batches it takes, and a batch smaller than BATCH_SIZE is the last.
  def transition_all!(now, thresholds, changed, still_held)
    target = target_sql(now, thresholds)
    after = 0
    loop do
      still_held.call
      found, moved = transition_batch!(target, now, after:)
      changed.concat(moved)
      break if found.size < BATCH_SIZE

      after = found.last
    end
  end
  private_class_method :transition_all!

  # One batch: the next BATCH_SIZE hosts whose status is not the one their last heartbeat implies, found in the narrow
  # host_liveness alone, among the rows of active hosts (evaluated, which a trigger on hosts keeps in step with the
  # enrollment state, so revoked and retired hosts are never read again; review of #220); then their host rows locked
  # (FOR NO KEY UPDATE, which a heartbeat's lock waits for, and active checked again under it), skipping rows a
  # heartbeat holds, for the next run. The statuses are then read again under those locks, by a new statement
  # that sees every heartbeat committed before them, and moved. Returns [ids found, ids moved].
  def transition_batch!(target, now, after:)
    Host.transaction do
      connection = HostLiveness.connection
      found = connection.select_values(HostLiveness.sanitize_sql_array([ <<~SQL, { after:, limit: BATCH_SIZE } ]), "Liveness candidates")
        SELECT l.host_id FROM host_liveness l
         WHERE l.evaluated AND l.host_id > :after AND l.liveness_status <> #{target} ORDER BY l.host_id LIMIT :limit
      SQL
      locked = found.empty? ? [] : Host.where(id: found).active.order(:id).lock("FOR NO KEY UPDATE SKIP LOCKED").pluck(:id)
      next [ found, [] ] if locked.empty?

      moved = connection.select_rows(HostLiveness.sanitize_sql_array([ <<~SQL, { ids: locked } ]), "Liveness transitions")
        UPDATE host_liveness l SET liveness_status = t.target
          FROM (SELECT l.host_id, l.liveness_status AS was, #{target} AS target FROM host_liveness l WHERE l.host_id IN (:ids)) t
         WHERE l.host_id = t.host_id AND t.was <> t.target
        RETURNING l.host_id, t.was, t.target
      SQL
      HostStatusEvent.insert_all!(moved.map { |id, from, to| { host_id: id, from_status: from, to_status: to, reason: "evaluation", occurred_at: now } }) if moved.any?
      [ found, moved.map(&:first) ]
    end
  end
  private_class_method :transition_batch!
end
