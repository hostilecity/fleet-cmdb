# The heartbeat's host-specific directives (DEC-20), read in one statement (#189): the rollout offer (Rollouts,
# agent_update), the outstanding report requests (ReportRequests, report_request), and whether a task is waiting
# (AgentTasks, tasks_available). Each service keeps its own query and builds its own directive; this only runs the
# three queries as scalar subqueries of one SELECT. The rollout row is still read FOR SHARE (Rollouts.directive_for)
# and the host row is already locked, so the lock order is unchanged.
#
# The writes stay where they were and happen only when there is something new: marking a host updating on its first
# offer, and marking report requests sent the first time a heartbeat carries them.
module HeartbeatDirectives
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
    columns = Rollouts::OFFER_COLUMNS.join(", ")
    rollout = Rollouts.offer_scope(host_id:, now:).select(Arel.sql("json_build_array(#{columns})"))
    requests = ReportRequests.outstanding_scope(host_id:, now:).select(Arel.sql("json_agg(json_build_array(report_requests.id, report_requests.report_type, report_requests.sent_at))"))
    tasks = AgentTasks.available_scope(host_id:).select(1)
    sql = "SELECT (#{rollout.to_sql}) AS rollout, (#{requests.to_sql}) AS report_requests, EXISTS (#{tasks.to_sql}) AS tasks_available"
    result = ApplicationRecord.connection.select_all(sql, "HeartbeatDirectives")
    result.columns.zip(result.cast_values.first).to_h
  end
  private_class_method :read
end
