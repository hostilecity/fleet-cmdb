require "rails_helper"

# Rate limits on the authenticated agent API (#191, server finding S-5, threat model V4 and V11): per credential and
# per address for failed authentication, both in the server process's memory, so neither writes to a database.
RSpec.describe "Agent API rate limits", type: :request do
  let!(:enrolled) { enrolled_host }
  let(:credential) { enrolled.last }
  let(:address) { "192.0.2.10" }
  let(:wrong) { "fa_EXAMPLEunknownkey000.#{'x' * 43}" }

  def poll(as, from: address)
    post_api("/api/v1/tasks/poll", { "schema_version" => 1, "agent_version" => "0.3.0" }, as, headers: { "REMOTE_ADDR" => from })
  end

  def statements_of
    statements = []
    callback = ->(*, payload) { statements << payload[:sql] unless payload[:name] == "SCHEMA" }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { yield }
    statements
  end

  describe "per credential" do
    it "counts in memory: no rate-limit statement in any database" do
      statements = statements_of { poll(credential) }
      expect(response).to have_http_status(:ok)
      expect(statements.join).not_to match(/solid_cache|cache_entries/)
      expect(AgentApi.credential_rate_limiter.count("rate-limit:agent_api:agent:#{credential.split('.').first}")).to eq(1)
    end

    it "refuses the request past the limit with 429 and Retry-After, and resets when the window ends" do
      limit = AgentApi.config.rate_limit[:to]
      limit.times { poll(credential) }
      expect(response).to have_http_status(:ok)
      poll(credential)
      expect_error(:too_many_requests, "rate_limited")
      expect(response.headers["Retry-After"]).to eq("60")
      later = AgentApi.credential_rate_limiter.clock + 61
      allow(AgentApi.credential_rate_limiter).to receive(:clock).and_return(later)
      poll(credential)
      expect(response).to have_http_status(:ok)
    end
  end

  describe "failed authentication per address (S-5)" do
    let(:limit) { AgentApi.config.failed_auth_rate_limit[:to] }

    it "refuses an address after too many failures, before authentication and with no database work" do
      limit.times { poll(wrong) }
      expect_error(:unauthorized, "unauthorized")
      statements = statements_of { poll(credential) } # a valid credential from that address waits too
      expect_error(:too_many_requests, "rate_limited")
      expect(response.headers["Retry-After"]).to eq("60")
      expect(statements).to be_empty
    end

    it "counts only failures, and only for the address they came from" do
      (limit * 2).times do
        AgentApi.credential_rate_limiter.clear # keep under the per-credential limit
        poll(credential)
      end
      expect(response).to have_http_status(:ok) # successes are never counted
      limit.times { poll(wrong) }
      poll(credential, from: "192.0.2.11")
      expect(response).to have_http_status(:ok)
    end

    it "lets the address in again once the window ends" do
      limit.times { poll(wrong) }
      later = AgentApi.failed_auth_rate_limiter.clock + 61
      allow(AgentApi.failed_auth_rate_limiter).to receive(:clock).and_return(later)
      poll(credential)
      expect(response).to have_http_status(:ok)
    end

    it "counts every kind of failed authentication the same (missing, malformed, revoked)" do
      host, revoked = enrolled_host
      host.revoke!(actor: Audit::SYSTEM)
      attempts = [ nil, "not-a-credential", revoked, wrong ]
      limit.times { |i| poll(attempts[i % attempts.size]) }
      poll(credential)
      expect_error(:too_many_requests, "rate_limited")
    end
  end
end
