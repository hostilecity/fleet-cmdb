module Api
  module V1
    # POST /api/v1/reports/config (FR-2.1, P2-S02). Validated against docs/api, checked against the fact
    # manifest (AgentApi::ConfigReport), then stored by ConfigRecorder in the request transaction, so an invalid
    # report writes nothing. A retried report (same report_id) is answered with duplicate: true. The body may be
    # gzip. The response carries the server's manifest version, so an agent with an older copy fetches it again.
    class ConfigReportsController < AuthenticatedController
      # Decompressed. A report at every limit of the current manifest is about 1.1 MiB of plain JSON (four
      # lists of up to 1,000 entries); a typical one is a few kilobytes. The compressed body is limited by
      # AgentApiRequestGuard.
      self.max_body_bytes = 4.megabytes
      self.accepts_gzip = true

      before_action :require_active_host!
      validates_body_with "config.request"
      atomic :create

      def create
        report = AgentApi::ConfigReport.new(payload)
        # Keys are limited to fact-key characters by the schema; control characters are removed anyway.
        logger.info("[agent_api] ignored unknown facts #{report.ignored_keys.join(' ').gsub(/[[:cntrl:]]/, '').truncate(1_000)}") if report.ignored_keys.any?
        result = ConfigRecorder.record!(host_id: current_host.id, credential_id: current_credential.id, report:)
        render json: { report_id: result.report_id, duplicate: result.duplicate, manifest_version: ConfigManifest.current.version }
      end
    end
  end
end
