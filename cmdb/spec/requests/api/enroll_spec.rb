require "rails_helper"

# POST /api/v1/enroll (P1-S05, DEC-04, FR-S.1, AC-1.5, AC-1.7)
RSpec.describe "POST /api/v1/enroll", type: :request do
  let!(:registered) { Enrollment::RegisterHost.call({ name: "VM 1", hostname: "vm-01.example.lan" }, actor: Audit::SYSTEM) }
  let(:host) { registered.first }
  let(:token) { registered.last }
  let(:machine_id) { "0123456789abcdef0123456789abcdef" }

  def body(**overrides)
    { schema_version: 1, agent_version: "0.1.0", token:, hostname: "vm-01.example.lan", machine_id: }.merge(overrides)
  end

  def enroll(payload = body, headers: api_headers)
    post "/api/v1/enroll", params: payload.is_a?(String) ? payload : payload.to_json, headers:
  end

  it "redeems the token for a credential and activates the host" do
    enroll

    expect(response).to have_http_status(:created)
    expect(ApiContract.errors("enroll.response", "v1", json)).to eq([])
    expect(json["host_name"]).to eq("VM 1")
    credential = AgentCredential.authenticate("Bearer #{json['credential']}")
    expect(credential).to have_attributes(host_id: host.id, machine_id:)
    expect(host.reload).to have_attributes(enrollment_state: "active", agent_version: "0.1.0", agent_schema_version: 1)
    entry = AuditEntry.for_target(host).chronological.last
    expect(entry).to have_attributes(action: Audit::Actions::HOST_ENROLLED, actor_type: "host", actor_id: host.id)
    expect(entry.changeset).to include("enrollment_state" => %w[pending active], "key_id" => [ nil, credential.key_id ])
  end

  describe "docs/api contract examples (NFR-5)" do
    ApiContract.examples.select { |e| e.version == "v1" && e.schema_name == "enroll.request" }.each do |example|
      it "#{example.kind == 'valid' ? 'accepts' : 'rejects'} #{example.name}" do
        payload = example.data
        payload["token"] = token if example.kind == "valid" && payload.key?("token")
        enroll(payload)
        if example.kind == "valid"
          expect(response).to have_http_status(:created)
        else
          expect_error(:bad_request, "validation_failed")
        end
      end
    end
  end

  describe "single use (DEC-04)" do
    it "cannot be redeemed twice" do
      enroll
      enroll
      expect_error(:gone, "enrollment_token_invalid")
      expect(host.agent_credentials.count).to eq(1)
    end

    it "cannot be redeemed after it expires" do
      travel_to(25.hours.from_now) { enroll }
      expect_error(:gone, "enrollment_token_invalid")
      expect(host.reload.enrollment_state).to eq("pending")
    end

    it "gives unknown, expired, used, and retired-host tokens the same response" do
      bodies = []
      capture = -> { bodies << json["error"].except("request_id") }
      enroll(body(token: "EXAMPLE-unknown-token-0000000000000000000000")).then { capture.call }
      travel_to(25.hours.from_now) { enroll }.then { capture.call }
      other_host, other_token = Enrollment::RegisterHost.call(attributes_for(:host), actor: Audit::SYSTEM)
      other_host.retire!(actor: Audit::SYSTEM)
      enroll(body(token: other_token)).then { capture.call }
      enroll.then { enroll }.then { capture.call }
      expect(bodies.uniq.size).to eq(1)
      expect(bodies.first["code"]).to eq("enrollment_token_invalid")
    end

    it "only accepts the newest token for a host" do
      newer = Enrollment::IssueToken.call(host:, actor: Audit::SYSTEM)
      enroll
      expect_error(:gone, "enrollment_token_invalid")
      enroll(body(token: newer))
      expect(response).to have_http_status(:created)
    end
  end

  describe "re-enrollment (FR-1.1, AC-1.5)" do
    it "keeps the old credential working until the new token is redeemed, then rejects it" do
      enroll
      old_credential = json["credential"]
      new_token = Enrollment::IssueToken.call(host:, actor: Audit::SYSTEM)
      expect(host.reload.enrollment_state).to eq("pending")
      expect(AgentCredential.authenticate("Bearer #{old_credential}")).to be_present

      enroll(body(token: new_token))
      expect(response).to have_http_status(:created)
      expect(AgentCredential.authenticate("Bearer #{old_credential}")).to be_nil
      expect(AgentCredential.authenticate("Bearer #{json['credential']}")).to be_present
      expect(host.reload.enrollment_state).to eq("active")
      expect(host.agent_credentials.active.count).to eq(1)
    end

    it "re-enrolls a revoked host" do
      enroll
      host.reload.revoke!(actor: Audit::SYSTEM)
      enroll(body(token: Enrollment::IssueToken.call(host:, actor: Audit::SYSTEM)))
      expect(response).to have_http_status(:created)
      expect(host.reload.enrollment_state).to eq("active")
    end
  end

  describe "secrets (NFR-1)" do
    it "never logs the token, the credential, or their digests" do
      log = captured_log { enroll }
      credential = json["credential"]
      expect(log).to include("Api::V1::EnrollmentsController#create")
      [ token, credential, credential.split(".").last, AgentApi.digest(token), AgentApi.digest(credential.split(".").last) ].each do |secret|
        expect(log).not_to include(secret)
      end
    end

    it "never writes the credential or token to the audit log" do
      enroll
      text = AuditEntry.for_target(host).pluck(:changeset).to_json
      expect(text).not_to include(token)
      expect(text).not_to include(json["credential"].split(".").last)
    end
  end

  describe "request handling (P1-S06)" do
    it "rejects malformed JSON, non-objects, and other content types without writing" do
      expect do
        enroll("{not json")
        expect_error(:bad_request, "validation_failed")
        enroll("[1, 2]")
        expect_error(:bad_request, "validation_failed")
        enroll(body, headers: { "CONTENT_TYPE" => "text/plain" })
        expect_error(:bad_request, "validation_failed")
      end.not_to change(AgentCredential, :count)
      expect(host.reload.enrollment_state).to eq("pending")
    end

    it "rejects deeply nested JSON" do
      enroll(body.merge(extra: JSON.parse("[" * 20 + "]" * 20)).to_json)
      expect_error(:bad_request, "validation_failed")
    end

    it "rejects an oversize body with 413 before parsing it" do
      expect { enroll(body(hostname: "a" * 5_000)) }.not_to change(AgentCredential, :count)
      expect_error(:payload_too_large, "payload_too_large")
      expect(EnrollmentToken.redeemable.where(host:)).to exist
    end

    it "lists each invalid field as a JSON Pointer without echoing values" do
      enroll(body(machine_id: "not-a-machine-id", hostname: 42))
      expect_error(:bad_request, "validation_failed")
      expect(json.dig("error", "details").pluck("pointer")).to contain_exactly("/machine_id", "/hostname")
      expect(json.to_json).not_to include("not-a-machine-id")
    end

    it "ignores and logs unknown fields by name only" do
      log = captured_log { enroll(body(future_field: "some value")) }
      expect(response).to have_http_status(:created)
      expect(log).to include("ignored unknown fields /future_field")
      expect(log).not_to include("some value")
    end

    it "returns 400, not 426, for a version that is not valid SemVer" do
      enroll(body(agent_version: "0.1.0-01"))
      expect_error(:bad_request, "validation_failed")
      expect(json.dig("error", "details").pluck("pointer")).to eq([ "/agent_version" ])
    end

    it "rolls the redemption back if the request fails after redeeming, so the agent can retry" do
      allow(Enrollment::Redeem).to receive(:call).and_wrap_original do |original, **args|
        original.call(**args)
        raise "failure while building the response"
      end
      enroll
      expect_error(:internal_server_error, "internal_error")
      expect(host.reload.enrollment_state).to eq("pending")
      expect(host.agent_credentials).to be_empty
      expect(EnrollmentToken.redeemable.where(host:)).to exist

      allow(Enrollment::Redeem).to receive(:call).and_call_original
      enroll
      expect(response).to have_http_status(:created)
    end

    it "returns 426 to agents older than the minimum version" do
      [ "0.0.9", "0.1.0-rc.1" ].each do |agent_version|
        enroll(body(agent_version:))
        expect_error(:upgrade_required, "agent_version_unsupported")
      end
      expect(host.reload.enrollment_state).to eq("pending")
    end

    it "rate-limits enrollment per client address with Retry-After" do
      limit = AgentApi.config.enroll_rate_limit[:to]
      limit.times { enroll(body(token: "EXAMPLE-unknown-token-0000000000000000000000")) }
      enroll
      expect_error(:too_many_requests, "rate_limited")
      expect(response.headers["Retry-After"]).to eq("60")
      expect(host.reload.enrollment_state).to eq("pending")
    end

    it "answers unknown /api/v1 paths with the JSON envelope" do
      get "/api/v1/hosts/1"
      expect_error(:not_found, "not_found")
      post "/api/v1"
      expect_error(:not_found, "not_found")
    end
  end
end
