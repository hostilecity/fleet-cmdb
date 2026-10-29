require "rails_helper"

# POST /api/v1/onboarding and POST /api/v1/onboarding/token (P1-ONBOARD, DEC-17, FR-S.1, AC-1.8, AC-1.5)
RSpec.describe "Agent onboarding API", type: :request do
  let(:operator) { create(:operator) }

  before { host! agent_host }

  def start(payload = onboarding_facts, ip: "192.0.2.10")
    post "/api/v1/onboarding", params: payload.is_a?(String) ? payload : payload.to_json, headers: api_headers.merge("REMOTE_ADDR" => ip)
  end

  def poll(device_code, ip: "192.0.2.10")
    post "/api/v1/onboarding/token", params: { schema_version: 1, agent_version: "0.1.0", device_code: }.to_json,
                                     headers: api_headers.merge("REMOTE_ADDR" => ip)
  end

  def started_request = OnboardingRequest.find_by_device_code(json["device_code"])

  describe "starting" do
    it "creates an open request, not a host, and returns the codes and approval URL" do
      expect { start }.not_to change(Host, :count)
      expect(response).to have_http_status(:created)
      expect(ApiContract.errors("onboarding.response", "v1", json)).to eq([])
      request = started_request
      expect(request).to have_attributes(state: "open", hostname: "vm-01.example.lan", machine_id: "0123456789abcdef0123456789abcdef",
                                         agent_version: "0.1.0", client_ip: "192.0.2.10", user_code: json["user_code"])
      expect(json).to include("verification_uri" => "https://fleet.example.lan/onboard",
                              "verification_uri_complete" => "https://fleet.example.lan/onboard/#{json['user_code']}",
                              "expires_in" => 600, "interval" => 5)
      expect(request.device_code_digest).to eq(AgentApi.digest(json["device_code"]))
      expect(OnboardingRequest.where(device_code_digest: json["device_code"])).to be_empty
    end

    it "strips control characters and caps the reported text, which is shown to operators" do
      start(onboarding_facts(hostname: "vm-01\u0007.example.lan", os: { "id" => "debian\u0000", "version_id" => nil, "pretty_name" => "Debian\u001b[31m" }))
      expect(started_request).to have_attributes(hostname: "vm-01.example.lan", os: { "id" => "debian", "version_id" => nil, "pretty_name" => "Debian[31m" })
    end

    it "caps open requests per client address and in total, creating nothing over the cap" do
      3.times { start(ip: "192.0.2.10") }
      expect { start(ip: "192.0.2.10") }.not_to change(OnboardingRequest, :count)
      expect_error(:too_many_requests, "rate_limited")
      expect(response.headers["Retry-After"]).to eq("60")
      start(ip: "192.0.2.11") # another address still can
      expect(response).to have_http_status(:created)

      2.times { |i| start(ip: "192.0.2.#{20 + i}") } # 6 open: the fleet-wide cap
      expect { start(ip: "192.0.2.30") }.not_to change(OnboardingRequest, :count)
      expect_error(:too_many_requests, "rate_limited")
    end

    it "frees the cap as requests expire or are decided" do
      3.times { start }
      travel_to(11.minutes.from_now) { start }
      expect(response).to have_http_status(:created)
    end

    it "rate-limits starts per client address" do
      limit = OnboardingRequest.config.start_rate_limit[:to]
      limit.times { |i| start(onboarding_facts(machine_id: "x"), ip: "192.0.2.10") } # invalid bodies still count
      start(ip: "192.0.2.10")
      expect_error(:too_many_requests, "rate_limited")
    end

    it "answers 404 on the dashboard hostname" do
      host! dashboard_host
      start
      expect(response).to have_http_status(:not_found)
      expect(response.body).to be_empty
    end
  end

  describe "polling and collecting" do
    before { start }

    let(:device_code) { json["device_code"] }
    let(:request_record) { started_request }

    it "answers pending while the request waits, and 429 when polled faster than the interval" do
      code = device_code
      poll(code)
      expect(response).to have_http_status(:accepted)
      expect(ApiContract.errors("onboarding-token.response", "v1", json)).to eq([])
      expect(json["status"]).to eq("pending")
      poll(code)
      expect_error(:too_many_requests, "rate_limited")
      expect(response.headers["Retry-After"]).to eq("5")
      travel_to(6.seconds.from_now) { poll(code) }
      expect(response).to have_http_status(:accepted)
    end

    it "limits polling per client address, whatever the device code, to stop floods" do
      AgentApi.config.rate_limit[:to].times { poll("EXAMPLE-unknown-device-code-00000000000000000000", ip: "192.0.2.50") }
      poll(device_code, ip: "192.0.2.50")
      expect_error(:too_many_requests, "rate_limited")
      expect(response.headers["Retry-After"]).to eq("60")
    end

    it "issues the credential once after approval, creating the host with the operator's fields (AC-1.8)" do
      code = device_code
      Onboarding::Approve.call(request: request_record, operator:, attributes: { name: "Media server", tags: "media, lab", description: "Jellyfin" })
      expect(Host.count).to eq(0) # nothing exists until the installer collects

      poll(code)
      expect(response).to have_http_status(:created)
      expect(ApiContract.errors("onboarding-token.response", "v1", json)).to eq([])
      expect(json["host_name"]).to eq("Media server")
      credential = AgentCredential.authenticate("Bearer #{json['credential']}")
      host = credential.host
      expect(host).to have_attributes(name: "Media server", hostname: "vm-01.example.lan", tags: %w[media lab], description: "Jellyfin",
                                      enrollment_state: "active", agent_version: "0.1.0", agent_schema_version: 1)
      expect(credential.machine_id).to eq("0123456789abcdef0123456789abcdef")
      expect(request_record.reload).to have_attributes(state: "collected", host:)

      entries = AuditEntry.for_target(host).chronological.pluck(:action, :actor_type, :actor_id)
      expect(entries).to eq([ [ Audit::Actions::HOST_CREATED, "operator", operator.id ], [ Audit::Actions::HOST_ENROLLED, "host", host.id ] ])
      expect(AuditEntry.for_target(host).chronological.last.changeset).to include("onboarding_request_id" => [ nil, request_record.id ])
      expect(AuditEntry.for_target(request_record).pluck(:action, :actor_id)).to eq([ [ Audit::Actions::ONBOARDING_APPROVED, operator.id ] ])

      travel_to(6.seconds.from_now) { poll(code) }
      expect_error(:gone, "onboarding_expired") # exactly once
      expect(AgentCredential.count).to eq(1)
    end

    it "answers 403 onboarding_rejected after rejection, leaving no host" do
      code = device_code
      Onboarding::Reject.call(request: request_record, operator:)
      poll(code)
      expect_error(:forbidden, "onboarding_rejected")
      expect(Host.count).to eq(0)
      expect(AuditEntry.for_target(request_record).pluck(:action)).to eq([ Audit::Actions::ONBOARDING_REJECTED ])
    end

    it "gives expired, unknown, and already-collected device codes the same 410" do
      code = device_code
      bodies = []
      travel_to(11.minutes.from_now) { poll(code) }
      bodies << json["error"].except("request_id")
      poll("EXAMPLE-unknown-device-code-00000000000000000000")
      bodies << json["error"].except("request_id")
      start(ip: "192.0.2.11")
      other = json["device_code"]
      Onboarding::Approve.call(request: started_request, operator:, attributes: { name: "Other" })
      poll(other, ip: "192.0.2.11")
      travel_to(6.seconds.from_now) { poll(other, ip: "192.0.2.11") }
      bodies << json["error"].except("request_id")
      expect(bodies.uniq.size).to eq(1)
      expect(bodies.first["code"]).to eq("onboarding_expired")
    end

    it "lets an approved request expire uncollected without creating a host" do
      code = device_code
      Onboarding::Approve.call(request: request_record, operator:, attributes: { name: "Media server" })
      travel_to(11.minutes.from_now) { poll(code) }
      expect_error(:gone, "onboarding_expired")
      expect(Host.count).to eq(0)
    end

    it "rolls the collection back if the response fails, so the installer can collect again" do
      code = device_code
      Onboarding::Approve.call(request: request_record, operator:, attributes: { name: "Media server" })
      allow(Onboarding::Collect).to receive(:call).and_wrap_original do |original, **args|
        original.call(**args)
        raise "failure while building the response"
      end
      poll(code)
      expect_error(:internal_server_error, "internal_error")
      expect([ Host.count, AgentCredential.count, request_record.reload.state ]).to eq([ 0, 0, "approved" ])

      allow(Onboarding::Collect).to receive(:call).and_call_original
      poll(code)
      expect(response).to have_http_status(:created)
    end
  end

  describe "re-enrollment (FR-1.1, AC-1.5)" do
    let!(:enrolled) { enrolled_host(name: "Media server", hostname: "vm-01.example.lan") }
    let(:host) { enrolled.first }
    let(:old_credential) { enrolled.last }

    it "keeps the old credential working until collection, then rejects it" do
      start
      code = json["device_code"]
      pending_token = Enrollment::IssueToken.call(host:, actor: Audit::SYSTEM)
      Onboarding::Approve.call(request: started_request, operator:, target_host: host)
      expect(host.reload.enrollment_state).to eq("pending")
      expect(AgentCredential.authenticate("Bearer #{old_credential}")).to be_present
      expect(EnrollmentToken.redeemable.where(host:)).to be_empty # only the newest path can enroll the host
      expect(pending_token).to be_present

      poll(code)
      expect(response).to have_http_status(:created)
      expect(AgentCredential.authenticate("Bearer #{old_credential}")).to be_nil
      expect(AgentCredential.authenticate("Bearer #{json['credential']}").host).to eq(host)
      expect(host.reload).to have_attributes(enrollment_state: "active", name: "Media server")
      expect(Host.count).to eq(1)
    end

    it "lets only the newest approval re-enroll the host: an earlier approved request can no longer collect (review of #61)" do
      start(ip: "192.0.2.10")
      first = json["device_code"]
      first_request = started_request
      start(ip: "192.0.2.11")
      second = json["device_code"]
      Onboarding::Approve.call(request: first_request, operator:, target_host: host)
      Onboarding::Approve.call(request: started_request, operator:, target_host: host)

      poll(first, ip: "192.0.2.10")
      expect_error(:gone, "onboarding_expired")
      poll(second, ip: "192.0.2.11")
      expect(response).to have_http_status(:created)
      expect(AgentCredential.authenticate("Bearer #{json['credential']}").host).to eq(host)
    end

    it "lets a newer enrollment token supersede an approved re-enrollment (review of #61)" do
      start
      code = json["device_code"]
      Onboarding::Approve.call(request: started_request, operator:, target_host: host)
      token = Enrollment::IssueToken.call(host:, actor: operator)

      poll(code)
      expect_error(:gone, "onboarding_expired")
      expect(host.reload.agent_credentials.active.sole.key_id).to eq(old_credential.split(".").first) # untouched
      Enrollment::Redeem.call(token:, machine_id: nil, agent_version: "0.1.0", schema_version: 1)
      expect(host.reload.enrollment_state).to eq("active")
    end

    it "supersedes only approved re-enrollments of that host" do
      other_host, = enrolled_host(hostname: "vm-02.example.lan")
      start(ip: "192.0.2.10")
      mine = started_request
      start(ip: "192.0.2.11")
      theirs = started_request
      start(ip: "192.0.2.12")
      new_host_request = started_request
      Onboarding::Approve.call(request: mine, operator:, target_host: host)
      Onboarding::Approve.call(request: theirs, operator:, target_host: other_host)
      Onboarding::Approve.call(request: new_host_request, operator:, attributes: { name: "New" })

      Enrollment::IssueToken.call(host:, actor: operator)
      expect(mine.reload.expired?).to be(true)
      expect([ theirs.reload.expired?, new_host_request.reload.expired? ]).to eq([ false, false ])
    end

    it "re-enrolls a revoked host" do
      host.revoke!(actor: Audit::SYSTEM)
      start
      code = json["device_code"]
      Onboarding::Approve.call(request: started_request, operator:, target_host: host)
      poll(code)
      expect(response).to have_http_status(:created)
      expect(host.reload.enrollment_state).to eq("active")
    end

    it "issues nothing if the host was retired after approval" do
      start
      code = json["device_code"]
      Onboarding::Approve.call(request: started_request, operator:, target_host: host)
      host.reload.retire!(actor: Audit::SYSTEM)
      poll(code)
      expect_error(:gone, "onboarding_expired")
      expect(host.agent_credentials.active).to be_empty
    end
  end

  describe "contract examples (NFR-5)" do
    ApiContract.examples.select { |e| e.version == "v1" && e.schema_name == "onboarding.request" }.each do |example|
      it "#{example.kind == 'valid' ? 'accepts' : 'rejects'} onboarding.request #{example.name}" do
        start(example.data)
        example.kind == "valid" ? expect(response).to(have_http_status(:created)) : expect_error(:bad_request, "validation_failed")
      end
    end

    ApiContract.examples.select { |e| e.version == "v1" && e.schema_name == "onboarding-token.request" }.each do |example|
      it "#{example.kind == 'valid' ? 'accepts' : 'rejects'} onboarding-token.request #{example.name}" do
        post "/api/v1/onboarding/token", params: example.data.to_json, headers: api_headers
        example.kind == "valid" ? expect_error(:gone, "onboarding_expired") : expect_error(:bad_request, "validation_failed")
      end
    end
  end

  describe "secrets (NFR-1)" do
    it "never logs or audits the device code, the user code, or the credential" do
      log = captured_log do
        start
        @code = json["device_code"]
        @user_code = json["user_code"]
        Onboarding::Approve.call(request: started_request, operator:, attributes: { name: "Media server" })
        poll(@code)
      end
      credential = json["credential"]
      expect(log).to include("Api::V1::OnboardingsController#token")
      [ @code, @user_code, credential, credential.split(".").last ].each { |secret| expect(log).not_to include(secret) }
      expect(AuditEntry.pluck(:changeset).to_json).not_to include(@code, credential.split(".").last)
    end
  end
end
