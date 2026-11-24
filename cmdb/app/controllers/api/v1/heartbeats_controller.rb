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
    # for a task now (P3-S03, AgentTasks.available?). The last three are read in one SELECT (HeartbeatDirectives) and
    # the intervals come from the per-process SettingsCache, so a host with nothing pending costs one extra SELECT and
    # no writes (#189).
    #
    # The request's `tasks` object, the agent's task capabilities (P3-A01), is stored in the same UPDATE, so tasks
    # are created only for hosts that support and enable the type (Host#task_exclusion_reason, P3-S02). It allows up
    # to 64 type ids in each of two lists, hence the larger body limit. Its `recovery` object, present only while the agent
    # runs in recovery mode (#180, ADR 0030), is stored in the same UPDATE too, and the dashboard shows the host as
    # recovering. Nothing in the response can put an agent into recovery mode or take it out. Its `units` object says
    # whether recovery mode is set up on the VM (#232); it is stored in the same UPDATE, written only when it changes,
    # and the fleet list can show the hosts without it. Its `process` object (#251) says when the agent process started,
    # how often systemd restarted it, and how the one before it stopped: stored the same way, written only when it
    # changes (on a new process), with each restart it shows counted for the fleet list's restart filter and, for a host
    # in an open rollout, for its stage's halt (Rollouts.restarts_seen!).
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
                                                 agent_time:, task_capabilities: payload["tasks"], recovery: payload["recovery"],
                                                 units: payload["units"], process: payload["process"])
        render json: { server_time: recorded_at.utc.iso8601, directives: directives(recorded_at, agent_time) }
      end

      private

      # Named entries in an object (DEC-20); a directive with nothing to say is left out.
      def directives(now, agent_time)
        intervals = SettingsCache.fetch(:agent_intervals) { Setting.agent_intervals }
        host_directives = HeartbeatDirectives.lookup(host_id: current_host.id, agent_version: payload["agent_version"], agent_time:, now:)
        { intervals: intervals.presence, **host_directives }.compact
      end
    end
  end
end
