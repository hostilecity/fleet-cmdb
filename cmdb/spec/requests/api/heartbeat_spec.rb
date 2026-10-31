require "rails_helper"

# POST /api/v1/heartbeat (P1-S07, FR-1.2, FR-1.4, AC-1.1, AC-1.2)
RSpec.describe "POST /api/v1/heartbeat", type: :request do
  let!(:enrolled) { enrolled_host }
  let(:host) { enrolled.first }
  let(:credential) { enrolled.last }

  def body(**overrides)
    { schema_version: 1, agent_version: "0.1.0", hostname: "vm-01.example.lan", uptime_seconds: 42, agent_time: "2026-01-01T12:00:00Z" }.merge(overrides)
  end

  def heartbeat(payload = body, as: credential)
    post "/api/v1/heartbeat", params: payload.to_json, headers: api_headers(as)
  end

  it "answers with the server time and an empty directives object (DEC-20)" do
    freeze_time do
      heartbeat
      expect(response).to have_http_status(:ok)
      expect(json).to eq("server_time" => Time.current.utc.iso8601, "directives" => {})
      expect(ApiContract.errors("heartbeat.response", "v1", json)).to eq([])
    end
  end

  it "records first contact and brings the host online at once (AC-1.1)" do
    expect(host.display_status).to eq("awaiting first contact")
    freeze_time do
      heartbeat(body(agent_version: "0.2.0"))
      expect(host.reload).to have_attributes(liveness_status: "online", last_seen_at: Time.current, first_seen_at: Time.current,
                                             agent_version: "0.2.0", agent_schema_version: 1)
    end
    expect(host.status_events.sole).to have_attributes(from_status: nil, to_status: "online", reason: "heartbeat")
  end

  it "keeps first_seen_at and writes no event while the host stays online" do
    heartbeat
    first_seen = host.reload.first_seen_at
    travel 1.minute
    expect { heartbeat }.not_to change(HostStatusEvent, :count)
    expect(host.reload.first_seen_at).to eq(first_seen)
    expect(host.last_seen_at).to be > first_seen
  end

  %w[stale offline].each do |status|
    it "returns a #{status} host to online and records the transition" do
      heartbeat
      host.reload.update_column(:liveness_status, status)
      heartbeat
      expect(host.reload.liveness_status).to eq("online")
      expect(host.status_events.chronological.last).to have_attributes(from_status: status, to_status: "online", reason: "heartbeat")
    end
  end

  it "never lets the agent's clock affect last_seen_at or liveness" do
    freeze_time do
      heartbeat(body(agent_time: "2001-01-01T00:00:00Z"))
      expect(host.reload).to have_attributes(last_seen_at: Time.current, agent_reported_at: Time.utc(2001, 1, 1), liveness_status: "online")
      Liveness.evaluate!
      expect(host.reload.liveness_status).to eq("online")
    end
    freeze_time { heartbeat(body(agent_time: "2099-12-31T23:59:59Z")) }
    seen_at = host.reload.last_seen_at
    expect(seen_at).to be <= Time.current
    travel_to(seen_at + 20.minutes) { Liveness.evaluate! }
    expect(host.reload.liveness_status).to eq("offline") # a future agent clock does not keep it online
  end

  it "writes no audit entries" do
    expect { heartbeat }.not_to change(AuditEntry, :count)
  end

  it "is one cheap write: a bounded number of queries and no other tables" do
    heartbeat # first contact writes an event; measure the steady state
    queries = []
    callback = ->(*, payload) { queries << payload[:sql] unless payload[:name] == "SCHEMA" || payload[:sql].match?(/\A(BEGIN|COMMIT|SAVEPOINT|RELEASE|ROLLBACK)/) }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { heartbeat }
    expect(response).to have_http_status(:ok)
    writes = queries.grep(/\A\s*(INSERT|UPDATE|DELETE)/i)
    expect(writes.size).to eq(1), writes.inspect
    expect(writes.first).to match(/UPDATE "hosts"/)
    # credential + host (authentication), host FOR UPDATE and credential re-check (under the lock), UPDATE
    expect(queries.size).to be <= 5, queries.inspect
    expect(queries.join).not_to match(/snapshot|audit_entries|host_status_events/)
  end

  it "stays one write after the credential last-use interval has passed (no agent_credentials write)" do
    heartbeat
    credential_record = host.agent_credentials.active.sole
    last_used = credential_record.reload.last_used_at
    travel(AgentCredential::LAST_USED_RESOLUTION + 1.minute) do
      writes = []
      callback = ->(*, payload) { writes << payload[:sql] if payload[:sql].match?(/\A\s*(INSERT|UPDATE|DELETE)/i) }
      ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { heartbeat }
      expect(response).to have_http_status(:ok)
      expect(writes.size).to eq(1), writes.inspect
      expect(writes.first).to match(/UPDATE "hosts"/)
    end
    expect(credential_record.reload.last_used_at).to eq(last_used)
  end

  it "reads the server clock only after locking the host row" do
    locked_at = nil
    callback = ->(*, payload) { locked_at ||= Time.current if payload[:sql].match?(/FROM "hosts".*FOR UPDATE/m) }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { heartbeat }
    expect(locked_at).to be_present
    expect(host.reload.last_seen_at).to be >= locked_at.floor(6)
    expect(Time.iso8601(json["server_time"])).to be >= locked_at.floor
  end

  it "never moves last_seen_at backwards behind a newer committed heartbeat" do
    heartbeat
    newer = 2.seconds.from_now.floor(6)
    host.reload.update_columns(last_seen_at: newer)
    heartbeat
    expect(host.reload.last_seen_at).to eq(newer)
    expect(host.first_seen_at).to be <= host.last_seen_at
  end

  describe "a state change between authentication and the write (review of #50)" do
    # Runs the transition after the request has authenticated and passed the active-host check, before
    # the heartbeat locks the host row.
    def after_authentication(&transition)
      allow_any_instance_of(Api::V1::HeartbeatsController).to receive(:require_active_host!).and_wrap_original do |original, *args|
        original.call(*args)
        transition.call
      end
    end

    it "refuses with 403 reenrollment_required when re-enrollment lands in between" do
      heartbeat
      after_authentication { Enrollment::IssueToken.call(host:, actor: Audit::SYSTEM) }
      expect { heartbeat }.not_to(change { host.reload.last_seen_at })
      expect_error(:forbidden, "reenrollment_required")
      expect(response.headers["Fleet-Enrollment-State"]).to eq("pending")
    end

    it "refuses with 401 when revocation or retirement lands in between" do
      %i[revoke! retire!].each do |transition|
        target, target_credential = enrolled_host
        after_authentication { target.reload.public_send(transition, actor: Audit::SYSTEM) }
        expect { heartbeat(as: target_credential) }.not_to change(HostStatusEvent, :count)
        expect_error(:unauthorized, "unauthorized")
        expect(target.reload.last_seen_at).to be_nil
      end
    end
  end

  describe "docs/api contract examples (NFR-5)" do
    # Valid examples include pre-release versions below the default minimum; the minimum check has its own spec.
    before { allow(AgentApi.config).to receive(:minimum_agent_version).and_return("0.0.0") }

    ApiContract.examples.select { |e| e.version == "v1" && e.schema_name == "heartbeat.request" }.each do |example|
      it "#{example.kind == 'valid' ? 'accepts' : 'rejects'} #{example.name}" do
        heartbeat(example.data)
        if example.kind == "valid"
          expect(response).to have_http_status(:ok)
        else
          expect_error(:bad_request, "validation_failed")
        end
      end
    end
  end

  describe "hosts that may not send heartbeats" do
    it "tells a re-enrolling host to redeem its new token (403 with Fleet-Enrollment-State)" do
      Enrollment::IssueToken.call(host:, actor: Audit::SYSTEM) # active -> pending; old credential still valid
      expect { heartbeat }.not_to(change { host.reload.attributes })
      expect_error(:forbidden, "reenrollment_required")
      expect(response.headers["Fleet-Enrollment-State"]).to eq("pending")
      expect(json.dig("error", "message")).to include("fleet-agent install --reenroll", "fleet-agent install --token")
    end

    it "refuses revoked and retired hosts with 401 (their credentials are revoked)" do
      %i[revoke! retire!].each do |transition|
        other_host, other_credential = enrolled_host
        other_host.public_send(transition, actor: Audit::SYSTEM)
        heartbeat(as: other_credential)
        expect_error(:unauthorized, "unauthorized")
        expect(other_host.reload.last_seen_at).to be_nil
      end
    end

    it "refuses a request without a credential" do
      heartbeat(as: nil)
      expect_error(:unauthorized, "unauthorized")
    end

    it "uses host_not_active for any other inactive state" do
      allow_any_instance_of(Host).to receive(:enrollment_state).and_return("revoked") # a credential that somehow outlived revocation
      heartbeat
      expect_error(:forbidden, "host_not_active")
      expect(response.headers).not_to have_key("Fleet-Enrollment-State")
    end
  end
end
