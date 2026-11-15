# The heartbeat's host-specific directives (DEC-20), read in one statement (#189): the rollout offer (Rollouts,
# agent_update), the outstanding report requests (ReportRequests, report_request), and whether a task is waiting
# (AgentTasks, tasks_available). Each service keeps its own query and builds its own directive; this only runs the
# three queries as scalar subqueries of one SELECT. The rollout row is read without a lock (Rollouts.directive_for,
# #199), and the host row is already locked.
#
# The writes stay where they were and happen only when there is something new: marking a host updating on its first
# offer, and marking report requests sent the first time a heartbeat carries them.
module HeartbeatDirectives
  OFFER_JSON = "json_build_array(rollout_hosts.id, rollout_hosts.state, rollouts.id, agent_releases.version)".freeze

  module_function

  # { agent_update:, report_request:, tasks_available: }, each nil when it has nothing to say. Runs in the heartbeat's
  # transaction, under the host row lock.
  def lookup(host_id:, agent_version:, agent_time:, now:)
    row = read(host_id:, now:)
    {
      agent_update: Rollouts.directive_from(row["rollout"], host_id:, agent_version:, now:),
      report_request: ReportRequests.directive_from(row["report_requests"] || [], agent_time:, now:),
      tasks_available: row["tasks_available"] ? {} : nil
    }
  end

  def read(host_id:, now:)
    # The columns of Rollouts::OFFER_COLUMNS, in its order (spec/services/heartbeat_directives_spec.rb checks they agree).
    rollout = Rollouts.offer_scope(host_id:, now:).select(Arel.sql(OFFER_JSON))
    requests = ReportRequests.outstanding_scope(host_id:, now:).select(Arel.sql("json_agg(json_build_array(report_requests.id, report_requests.report_type, report_requests.sent_at))"))
    tasks = AgentTasks.available_scope(host_id:).select(1)
    # Composed with Arel, not with to_sql, so every value stays a bind parameter ($1, $2, ...) and the statement text
    # is the same on every heartbeat: PostgreSQL then prepares it once per connection instead of planning it on every
    # heartbeat (review of #209). Active Record would not prepare it by itself, because the scopes hold SQL text (the
    # stage comparison, the offer's due time) and it prepares no statement with SQL literals, as they might carry
    # values. Here they are constants, so the text is compiled once per call with the connection's visitor and passed
    # as preparable. spec/services/heartbeat_directives_spec.rb checks that the statement is prepared.
    select = Arel::SelectManager.new.project(Arel::Nodes::Grouping.new(rollout.arel).as("rollout"),
                                             Arel::Nodes::Grouping.new(requests.arel).as("report_requests"),
                                             tasks.arel.exists.as("tasks_available"))
    connection = ApplicationRecord.connection
    sql, binds = connection.visitor.compile(select.ast, Arel::Collectors::Composite.new(Arel::Collectors::SQLString.new, Arel::Collectors::Bind.new))
    result = connection.select_all(sql, "HeartbeatDirectives", binds, preparable: true)
    result.columns.zip(result.cast_values.first).to_h
  end
  private_class_method :read
end
