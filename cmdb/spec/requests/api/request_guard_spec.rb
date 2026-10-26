require "rails_helper"

# lib/middleware/agent_api_request_guard.rb (P1-S06, NFR-1)
RSpec.describe AgentApiRequestGuard do
  let(:downstream) { ->(env) { [ 200, {}, [ env["rack.input"].read ] ] } }
  let(:guard) { described_class.new(downstream, max_body_bytes: 10) }

  def call(path, body, content_length: body.bytesize)
    env = Rack::MockRequest.env_for(path, method: "POST", input: body)
    content_length ? env["CONTENT_LENGTH"] = content_length.to_s : env.delete("CONTENT_LENGTH")
    env["action_dispatch.request_id"] = "req-1"
    [ guard.call(env), env ]
  end

  it "rejects an oversize body by Content-Length without reading it" do
    (status, _headers, body), = call("/api/v1/enroll", "x" * 11)
    expect(status).to eq(413)
    expect(JSON.parse(body.join)).to eq("error" => { "code" => "payload_too_large", "message" => "The request body is too large.", "request_id" => "req-1" })
  end

  it "rejects an oversize body sent without Content-Length" do
    (status, *), = call("/api/v1/enroll", "x" * 11, content_length: nil)
    expect(status).to eq(413)
  end

  it "passes smaller bodies through intact and stops Rails parsing them as parameters" do
    (status, _headers, body), env = call("/api/v1/enroll", '{"a":1}')
    expect(status).to eq(200)
    expect(body.join).to eq('{"a":1}')
    expect(env["action_dispatch.request.request_parameters"]).to eq({})
  end

  it "leaves other paths alone" do
    (status, *), env = call("/up", "x" * 11)
    expect(status).to eq(200)
    expect(env).not_to have_key("action_dispatch.request.request_parameters")
  end

  it "is installed with a 1 MB limit in the application" do
    post "/api/v1/enroll", params: "x" * (AgentApiRequestGuard::MAX_BODY_BYTES + 1), headers: { "CONTENT_TYPE" => "application/json" }
    expect(response).to have_http_status(:payload_too_large)
    expect(response.parsed_body.dig("error", "request_id")).to eq(response.headers["X-Request-Id"])
  end
end
