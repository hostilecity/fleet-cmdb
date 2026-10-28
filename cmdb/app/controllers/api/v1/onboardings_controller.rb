module Api
  module V1
    # Agent onboarding (DEC-17, P1-ONBOARD): the installer starts a request, shows the operator a code, and
    # polls until the request is approved, rejected, or expired. Unauthenticated, on the agent hostname only,
    # and rate-limited per client address; Onboarding::Start also caps how many requests may be open.
    class OnboardingsController < BaseController
      self.max_body_bytes = 4.kilobytes

      rate_limit to: OnboardingRequest.config.start_rate_limit[:to], within: OnboardingRequest.config.start_rate_limit[:within],
                 by: -> { request.remote_ip }, store: AgentApi.rate_limit_store, name: "onboarding", scope: "agent_api",
                 with: -> { rate_limited!(OnboardingRequest.config.start_rate_limit[:within]) }, only: :create
      # Polling is limited per device code by Onboarding::Collect; this per-address limit only stops floods.
      rate_limit to: AgentApi.config.rate_limit[:to], within: AgentApi.config.rate_limit[:within],
                 by: -> { request.remote_ip }, store: AgentApi.rate_limit_store, name: "onboarding_token", scope: "agent_api",
                 with: -> { rate_limited!(AgentApi.config.rate_limit[:within]) }, only: :token
      validates_body_with "onboarding.request", only: :create
      validates_body_with "onboarding-token.request", only: :token
      # The credential and the host commit only once the response is built, so a failure after collecting
      # never consumes the request without the installer receiving its credential.
      atomic :create, :token

      # POST /api/v1/onboarding
      def create
        started = Onboarding::Start.call(facts: payload, client_ip: request.remote_ip)
        record = started.record
        logger.info("[onboarding] started request #{record.id}")
        render status: :created, json: {
          device_code: started.device_code, user_code: record.user_code,
          verification_uri: OnboardingRequest.verification_uri, verification_uri_complete: record.user_code_url,
          expires_in: (record.expires_at - Time.current).ceil, interval: OnboardingRequest.config.poll_interval.to_i,
          server_time:
        }
      rescue AgentApi::RateLimited
        rate_limited!(1.minute)
      end

      # POST /api/v1/onboarding/token
      def token
        result = Onboarding::Collect.call(device_code: payload["device_code"], agent_version: payload["agent_version"],
                                          schema_version: payload["schema_version"])
        if result.status == :pending
          render status: :accepted, json: { status: "pending", server_time: }
        else
          logger.info("[onboarding] credential collected for host #{result.host.id}")
          render status: :created, json: { status: "approved", credential: result.credential, host_name: result.host.name, server_time: }
        end
      rescue AgentApi::RateLimited
        rate_limited!(OnboardingRequest.config.poll_interval)
      end

      private

      def server_time = Time.current.utc.iso8601
    end
  end
end
