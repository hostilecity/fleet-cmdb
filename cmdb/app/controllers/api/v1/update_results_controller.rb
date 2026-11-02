module Api
  module V1
    # POST /api/v1/update-results (FR-S.5, P1-UPDATES, ADR 0018): the agent reports how an update ended
    # (succeeded, failed, or rolled_back with a reason). Stored in the host's update history and audited by
    # Rollouts.record_result!; a failure or rollback halts the rollout. A retried result (same report_id) is
    # answered with duplicate: true.
    #
    # Exempt from the minimum agent version: an agent that is too old for the other endpoints must still be
    # able to say that its update failed, or that it rolled back. Reports still get 426.
    class UpdateResultsController < AuthenticatedController
      self.max_body_bytes = 8.kilobytes
      self.enforces_minimum_agent_version = false

      before_action :require_active_host!
      validates_body_with "update-result.request"
      atomic :create

      def create
        result = Rollouts.record_result!(host_id: current_host.id, credential_id: current_credential.id, payload:)
        render json: { report_id: result.report_id, duplicate: result.duplicate }
      end
    end
  end
end
