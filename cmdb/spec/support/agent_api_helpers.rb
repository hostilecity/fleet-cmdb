# Helpers for agent API request specs (P1-API-AUTH).
module AgentApiHelpers
  # An active host with a credential, enrolled through the real flow. Returns [host, plaintext_credential].
  def enrolled_host(**attributes)
    host, token = Enrollment::RegisterHost.call(attributes_for(:host).merge(attributes), actor: Audit::SYSTEM)
    credential = Enrollment::Redeem.call(token:, machine_id: nil, agent_version: "0.1.0", schema_version: 1)
    [ host.reload, credential ]
  end

  def api_headers(credential = nil)
    { "CONTENT_TYPE" => "application/json" }.tap { |h| h["Authorization"] = "Bearer #{credential}" if credential }
  end

  def json = response.parsed_body

  def expect_error(status, code)
    expect(response).to have_http_status(status)
    expect(json.dig("error", "code")).to eq(code)
    expect(ApiContract.errors("error.response", "v1", json)).to eq([]), "error body does not match docs/api error.response"
    expect(json.dig("error", "request_id")).to eq(response.headers["X-Request-Id"])
  end

  # Captures everything logged while the block runs.
  def captured_log
    io = StringIO.new
    logger = ActiveSupport::Logger.new(io)
    logger.level = :debug
    Rails.logger.broadcast_to(logger)
    ActiveRecord::Base.logger&.broadcast_to(logger) unless ActiveRecord::Base.logger.equal?(Rails.logger)
    yield
    io.string
  ensure
    Rails.logger.stop_broadcasting_to(logger)
    ActiveRecord::Base.logger&.stop_broadcasting_to(logger) unless ActiveRecord::Base.logger.equal?(Rails.logger)
  end
end

RSpec.configure do |config|
  config.include AgentApiHelpers
  config.include ActiveSupport::Testing::TimeHelpers
  config.before { AgentApi.rate_limit_store.clear }
end
