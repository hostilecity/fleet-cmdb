module Api
  module V1
    # POST /api/v1/heartbeat (FR-1.2, P1-S07). Updates last_seen_at from the server clock and the agent
    # version; the agent's reported time is stored separately and never used for liveness. A host that was
    # not online becomes online immediately, with a status history row. No audit entries and no credential
    # last-use write: a steady-state heartbeat is exactly one UPDATE. The host and credential are re-checked
    # under the host row lock, so a revocation or re-enrollment that lands mid-request is still refused.
    #
    # The response carries the directives (DEC-20, P1-UPDATES): the intervals the operator set, and the
    # agent_update directive for a host in an open rollout stage that runs an older version. Heartbeats are
    # exempt from the minimum agent version, so an agent that is too old for the other endpoints still learns
    # of the release that updates it (FR-S.5). The report_request directive lists the report types an operator
    # asked for that no report has answered yet (P2-S03, ReportRequests). tasks_available tells the agent to poll
    # for a task now (P3-S03, AgentTasks.available?). A host with nothing pending costs four extra SELECTs, no writes.
    #
    # The request's `tasks` object, the agent's task capabilities (P3-A01), is stored in the same UPDATE, so tasks
    # are created only for hosts that support and enable the type (Host#task_exclusion_reason, P3-S02). It allows up
    # to 64 type ids in each of two lists, hence the larger body limit.
    class HeartbeatsController < AuthenticatedController
      self.max_body_bytes = 32.kilobytes
      self.records_credential_use = false
      self.enforces_minimum_agent_version = false

      before_action :require_active_host!
      validates_body_with "heartbeat.request"
      atomic :create

      def create
        agent_time = Time.iso8601(payload["agent_time"])
        recorded_at = Liveness.record_heartbeat!(host_id: current_host.id, credential_id: current_credential.id,
                                                 agent_version: payload["agent_version"], agent_schema_version: payload["schema_version"],
                                                 agent_time:, task_capabilities: payload["tasks"])
        render json: { server_time: recorded_at.utc.iso8601, directives: directives(recorded_at, agent_time) }
      end

      private

      # Named entries in an object (DEC-20); a directive with nothing to say is left out.
      def directives(now, agent_time)
        intervals = Setting.agent_intervals
        update = Rollouts.directive_for(host_id: current_host.id, agent_version: payload["agent_version"], now:)
        report_request = ReportRequests.directive_for(host_id: current_host.id, agent_time:, now:)
        tasks_available = AgentTasks.available?(host_id: current_host.id) ? {} : nil
        { intervals: intervals.presence, agent_update: update, report_request:, tasks_available: }.compact
      end
    end
  end
end
