module Api
  module V1
    # POST /api/v1/reports/inventory (FR-1.3, P1-INVENTORY). Validated against docs/api, normalised and
    # checked (AgentApi::InventoryReport), then stored by InventoryRecorder in the request transaction, so an
    # invalid report writes nothing. A retried report (same report_id) is answered with duplicate: true.
    class InventoryReportsController < AuthenticatedController
      # 64 disks and 64 interfaces of 32 addresses each fit well within this.
      self.max_body_bytes = 256.kilobytes

      before_action :require_active_host!
      validates_body_with "inventory.request"
      atomic :create

      def create
        report = AgentApi::InventoryReport.new(payload)
        result = InventoryRecorder.record!(host_id: current_host.id, credential_id: current_credential.id, report:)
        render json: { report_id: result.report_id, duplicate: result.duplicate }
      end
    end
  end
end
