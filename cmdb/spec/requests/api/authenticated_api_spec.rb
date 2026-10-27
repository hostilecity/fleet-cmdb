require "rails_helper"

# The authenticated agent API foundation (P1-S04, P1-S06; FR-S.1, FR-S.2, AC-1.5, AC-1.6). Real authenticated
# endpoints arrive with P1-HEARTBEAT and P1-INVENTORY; until then a probe controller defined here exercises
# Api::V1::AuthenticatedController exactly as they will.
module Api
  module V1
    class ProbesController < AuthenticatedController
      validates_body_with "heartbeat.request", only: :create
      atomic :create

      def show
        render json: { host_id: current_host.id, name: current_host.name }
      end

      # Writes, then fails when asked to, so the spec can prove the request leaves nothing behind.
      def create
        current_host.edit!({ notes: "written by probe" }, actor: current_host)
        raise "probe failure with secret-looking detail" if payload["hostname"] == "fail.example.lan"

        render json: { ok: true }
      end

      def active_only
        require_active_host!
        render json: { ok: true }
      end
    end
  end
end

RSpec.describe "Authenticated agent API", type: :request do
  around do |example|
    with_routing do |routes|
      routes.draw do
        namespace :api do
          namespace :v1 do
            get "probe", to: "probes#show"
            post "probe", to: "probes#create"
            get "probe/active", to: "probes#active_only"
          end
        end
      end
      example.run
    end
  end

  let!(:enrolled_a) { enrolled_host(name: "Host A") }
  let(:host_a) { enrolled_a.first }
  let(:credential_a) { enrolled_a.last }
  let(:heartbeat) { { schema_version: 1, agent_version: "0.1.0", hostname: "vm-01.example.lan", uptime_seconds: 5, agent_time: "2026-01-01T12:00:00Z" } }

  def probe(credential, headers: {})
    get "/api/v1/probe", headers: api_headers(credential).merge(headers)
  end

  describe "authentication (FR-S.1)" do
    it "identifies the host by its credential" do
      probe(credential_a)
      expect(response).to have_http_status(:ok)
      expect(json).to eq("host_id" => host_a.id, "name" => "Host A")
    end

    it "gives missing, malformed, unknown, wrong, revoked, and retired-host credentials the same 401" do
      key_id, secret = credential_a.split(".")
      revoked_host, revoked_credential = enrolled_host
      revoked_host.revoke!(actor: Audit::SYSTEM)
      retired_host, retired_credential = enrolled_host
      retired_host.retire!(actor: Audit::SYSTEM)

      attempts = {
        "missing" => -> { get "/api/v1/probe", headers: api_headers },
        "not bearer" => -> { probe(nil, headers: { "Authorization" => "Basic #{Base64.strict_encode64("#{key_id}:#{secret}")}" }) },
        "malformed" => -> { probe("not-a-credential") },
        "unknown key" => -> { probe("fa_EXAMPLEunknownkey000.#{secret}") },
        "wrong secret" => -> { probe("#{key_id}.#{'x' * 43}") },
        "revoked" => -> { probe(revoked_credential) },
        "retired host" => -> { probe(retired_credential) }
      }
      bodies = attempts.to_h do |name, attempt|
        attempt.call
        expect_error(:unauthorized, "unauthorized")
        [ name, json["error"].except("request_id") ]
      end
      expect(bodies.values.uniq.size).to eq(1), bodies.inspect
    end

    it "rejects a revoked credential on the very next request (AC-1.5)" do
      probe(credential_a)
      expect(response).to have_http_status(:ok)
      host_a.revoke!(actor: Audit::SYSTEM)
      probe(credential_a)
      expect_error(:unauthorized, "unauthorized")
    end

    it "rejects the old credential as soon as re-enrollment completes (AC-1.5)" do
      token = Enrollment::IssueToken.call(host: host_a, actor: Audit::SYSTEM)
      probe(credential_a)
      expect(response).to have_http_status(:ok) # still valid until the new token is redeemed (FR-1.1)
      new_credential = Enrollment::Redeem.call(token:, machine_id: nil, agent_version: "0.1.0", schema_version: 1)
      probe(credential_a)
      expect_error(:unauthorized, "unauthorized")
      probe(new_credential)
      expect(response).to have_http_status(:ok)
    end

    it "records last use at most every few minutes" do
      credential = host_a.agent_credentials.active.sole
      probe(credential_a)
      first = credential.reload.last_used_at
      expect(first).to be_present
      probe(credential_a)
      expect(credential.reload.last_used_at).to eq(first)
      travel_to(AgentCredential::LAST_USED_RESOLUTION.from_now + 1.second) { probe(credential_a) }
      expect(credential.reload.last_used_at).to be > first
    end

    it "refuses hosts that are not active where an endpoint requires it" do
      get "/api/v1/probe/active", headers: api_headers(credential_a)
      expect(response).to have_http_status(:ok)
      Enrollment::IssueToken.call(host: host_a, actor: Audit::SYSTEM) # active -> pending, credential still valid
      get "/api/v1/probe/active", headers: api_headers(credential_a)
      expect_error(:forbidden, "reenrollment_required") # P1-HEARTBEAT: tell the agent to redeem its new token
      expect(response.headers["Fleet-Enrollment-State"]).to eq("pending")
    end
  end

  describe "host isolation (AC-1.6)" do
    let!(:enrolled_b) { enrolled_host(name: "Host B") }
    let(:host_b) { enrolled_b.first }

    it "ignores any host identifier in the request" do
      get "/api/v1/probe", params: { host_id: host_b.id, id: host_b.id }, headers: { "Authorization" => "Bearer #{credential_a}" }
      expect(json["host_id"]).to eq(host_a.id)
    end

    it "writes only to the authenticated host" do
      post "/api/v1/probe", params: heartbeat.merge(host_id: host_b.id).to_json, headers: api_headers(credential_a)
      expect(response).to have_http_status(:ok)
      expect(host_a.reload.notes).to eq("written by probe")
      expect(host_b.reload.notes).to be_nil
    end

    it "has no API controller that looks a host up from the request" do
      sources = Rails.root.glob("app/controllers/api/**/*.rb").to_h { |path| [ path.relative_path_from(Rails.root).to_s, path.read ] }
      expect(sources).not_to be_empty
      sources.each do |path, source|
        expect(source).not_to match(/\bHost\.(find|where|find_by|lock|unscoped)\b|params\[:host/), "#{path} looks up a host from the request"
      end
    end
  end

  describe "request handling (P1-S06)" do
    it "validates the body against docs/api and lists each problem" do
      post "/api/v1/probe", params: heartbeat.merge(uptime_seconds: "5", agent_time: "yesterday").to_json, headers: api_headers(credential_a)
      expect_error(:bad_request, "validation_failed")
      expect(json.dig("error", "details").pluck("pointer")).to contain_exactly("/uptime_seconds", "/agent_time")
      expect(host_a.reload.notes).to be_nil
    end

    it "accepts unknown fields, ignoring them" do
      post "/api/v1/probe", params: heartbeat.merge(future: { nested: true }).to_json, headers: api_headers(credential_a)
      expect(response).to have_http_status(:ok)
    end

    it "rolls back everything when the request fails part-way, and hides the cause" do
      expect do
        post "/api/v1/probe", params: heartbeat.merge(hostname: "fail.example.lan").to_json, headers: api_headers(credential_a)
      end.not_to change(AuditEntry, :count)
      expect_error(:internal_server_error, "internal_error")
      expect(response.body).not_to include("secret-looking")
      expect(host_a.reload.notes).to be_nil
    end

    it "throttles a burst from one credential without affecting another (429 with Retry-After)" do
      _host_b, credential_b = enrolled_host
      limit = AgentApi.config.rate_limit[:to]
      limit.times { probe(credential_a) }
      expect(response).to have_http_status(:ok)
      probe(credential_a)
      expect_error(:too_many_requests, "rate_limited")
      expect(response.headers["Retry-After"]).to eq("60")
      probe(credential_b)
      expect(response).to have_http_status(:ok)
    end

    it "checks credentials before reading the body" do
      post "/api/v1/probe", params: "{not json", headers: api_headers("fa_EXAMPLEunknownkey000.#{'x' * 43}")
      expect_error(:unauthorized, "unauthorized")
    end
  end
end

# Outside the probe routes above: checks the application's real route table.
RSpec.describe "Agent API routes" do
  it "serves every /api/v1 route except enrollment and the not-found catch-all through AuthenticatedController (AC-1.6)" do
    api_routes = Rails.application.routes.routes.select { |route| route.path.spec.to_s.start_with?("/api/v1") }
    controllers = api_routes.filter_map { |route| route.defaults[:controller] }.uniq
    expect(controllers).to include("api/v1/enrollments", "api/v1/base")
    (controllers - [ "api/v1/enrollments", "api/v1/base" ]).each do |name|
      expect("#{name}_controller".camelize.constantize).to be < Api::V1::AuthenticatedController
    end
    expect(api_routes.select { |route| route.defaults[:controller] == "api/v1/base" }.map { |route| route.defaults[:action] }.uniq).to eq([ "not_found" ])
  end
end
