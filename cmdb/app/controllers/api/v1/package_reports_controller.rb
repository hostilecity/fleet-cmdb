module Api
  module V1
    # POST /api/v1/reports/packages (FR-2.3, P2-S08). Validated against docs/api, checked
    # (AgentApi::PackageReport), then stored by PackageRecorder in the request transaction, so an invalid report
    # writes nothing. A retried report (same report_id) is answered with duplicate: true. The body may be gzip.
    class PackageReportsController < AuthenticatedController
      # Decompressed. 20,000 packages (the schema's limit) of about 130 bytes each fit; a typical Debian 13
      # server has a few thousand. The compressed body is limited by AgentApiRequestGuard.
      self.max_body_bytes = 4.megabytes
      self.accepts_gzip = true

      before_action :require_active_host!
      validates_body_with "packages.request"
      atomic :create

      def create
        report = AgentApi::PackageReport.new(payload)
        result = PackageRecorder.record!(host_id: current_host.id, credential_id: current_credential.id, report:)
        render json: { report_id: result.report_id, duplicate: result.duplicate }
      end
    end
  end
end
