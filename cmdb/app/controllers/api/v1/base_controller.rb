module Api
  module V1
    # Foundation for every /api/v1 endpoint (FR-S.2, DEC-08, P1-S06):
    #
    # - JSON bodies are read and parsed here, not through Rails params, so the size limit applies before any
    #   parsing and every failure gets the documented error envelope.
    # - Bodies are validated against docs/api/schemas for the body's schema_version. Unknown fields are
    #   ignored and logged by path (never by value); wrong types and out-of-range values are rejected.
    # - Agents older than the configured minimum get 426 agent_version_unsupported.
    # - Write actions run in one transaction, so a failed request leaves nothing half-written.
    # - Unexpected errors return 500 internal_error without internals.
    class BaseController < ActionController::API
      JSON_MAX_NESTING = 16
      # Tells an agent its host is waiting for a new enrollment token to be redeemed (docs/api/README.md).
      ENROLLMENT_STATE_HEADER = "Fleet-Enrollment-State"

      class_attribute :max_body_bytes, default: 64.kilobytes

      rescue_from StandardError, with: :render_unexpected_error
      rescue_from AgentApi::Error, with: :render_api_error

      before_action { Current.request_id = request.request_id }

      # Validates the JSON body against docs/api/schemas/v<schema_version>/<name>.schema.json for the
      # given actions and exposes it as #payload.
      def self.validates_body_with(schema_name, **options)
        before_action(**options) { @payload = validated_body(schema_name) }
      end

      # Runs the given actions inside one database transaction.
      def self.atomic(*actions)
        around_action :in_transaction, only: actions
      end

      def not_found
        raise AgentApi::NotFound
      end

      private

      attr_reader :payload

      def validated_body(schema_name)
        data = parse_body
        check_agent_version!(data["agent_version"])
        version = AgentApi::Schema.exists?(schema_name, data["schema_version"]) ? data["schema_version"] : AgentApi::Schema.latest_version
        errors = AgentApi::Schema.errors(schema_name, version, data)
        raise AgentApi::ValidationFailed.new(details: errors) if errors.any?

        unknown = AgentApi::Schema.undeclared_pointers(schema_name, version, data)
        logger.info("[agent_api] ignored unknown fields #{unknown.join(' ')}") if unknown.any?
        data
      end

      def parse_body
        unless request.media_type == "application/json"
          raise AgentApi::ValidationFailed.new("The request body must be JSON (Content-Type: application/json).")
        end

        data = JSON.parse(read_body, max_nesting: JSON_MAX_NESTING)
        raise AgentApi::ValidationFailed.new("The request body must be a JSON object.") unless data.is_a?(Hash)

        data
      rescue JSON::ParserError, JSON::NestingError, EncodingError
        raise AgentApi::ValidationFailed.new("The request body is not valid JSON.")
      end

      # Reads at most max_body_bytes, whether or not Content-Length is sent.
      def read_body
        raise AgentApi::PayloadTooLarge if request.content_length.to_i > max_body_bytes

        body = request.body.read(max_body_bytes + 1).to_s
        raise AgentApi::PayloadTooLarge if body.bytesize > max_body_bytes

        body.force_encoding(Encoding::UTF_8)
      end

      def check_agent_version!(reported)
        version = AgentApi::AgentVersion.parse(reported) or return # an invalid version fails schema validation

        minimum = AgentApi::AgentVersion.parse(AgentApi.config.minimum_agent_version)
        raise AgentApi::AgentVersionUnsupported if version < minimum
      end

      def in_transaction(&)
        ApplicationRecord.transaction(&)
      end

      def render_api_error(error)
        response.set_header("Retry-After", @retry_after.to_s) if error.is_a?(AgentApi::RateLimited) && @retry_after
        response.set_header(ENROLLMENT_STATE_HEADER, "pending") if error.is_a?(AgentApi::ReenrollmentRequired)
        body = { code: error.code, message: error.message, request_id: request.request_id, details: error.details.presence }
        render json: { error: body.compact }, status: error.status
      end

      def render_unexpected_error(error)
        detail = Rails.env.production? ? "" : ": #{error.message}"
        logger.error("[agent_api] unhandled #{error.class}#{detail}\n#{Rails.backtrace_cleaner.clean(error.backtrace.to_a).first(5).join("\n")}")
        render_api_error(AgentApi::InternalError.new)
      end

      def rate_limited!(within)
        @retry_after = within.to_i
        raise AgentApi::RateLimited
      end
    end
  end
end
