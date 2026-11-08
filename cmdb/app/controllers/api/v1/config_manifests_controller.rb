module Api
  module V1
    # GET /api/v1/manifest/config (FR-2.1, P2-S01): the fact manifest an agent collects and reports against.
    #
    # Authenticated as a host, like the reports it is read for, and only for an active host. The request has no
    # body and so no agent version: it is exempt from the minimum-version check (an agent too old to report gets
    # 426 from the report itself). Served with a strong ETag, so an agent that already has the current manifest
    # is told 304 and does not download it again.
    class ConfigManifestsController < AuthenticatedController
      before_action :require_active_host!

      def show
        manifest = ConfigManifest.current
        return unless stale?(strong_etag: manifest.etag, public: false)

        render json: manifest.to_json
      end
    end
  end
end
