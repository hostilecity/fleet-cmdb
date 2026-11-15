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

    it "still lets in a key id that authenticated recently, so a client sharing the address cannot lock agents out" do
      poll(credential) # this agent authenticated a moment ago
      limit.times { poll(wrong) } # a hostile client behind the same address
      poll(credential)
      expect(response).to have_http_status(:ok)
      _other_host, unseen = enrolled_host # an agent not seen in this process recently waits like everyone else
      poll(unseen)
      expect_error(:too_many_requests, "rate_limited")
    end

    it "remembers a key id for 15 minutes from its last success, then not" do
      poll(credential)
      limit.times { poll(wrong) }
      later = AgentApi.recent_credentials.clock + AgentApi::RECENT_CREDENTIAL_TTL.to_f + 1
      allow(AgentApi.recent_credentials).to receive(:clock).and_return(later)
      poll(credential)
      expect_error(:too_many_requests, "rate_limited")
    end

    it "counts the failures of a recent key id, and stops letting it through past the limit" do
      poll(credential)
      key_id = credential.split(".").first
      limit.times { poll(wrong) }
      limit.times { poll("#{key_id}.#{'y' * 43}") } # the key id is not secret: a guesser may use it
      expect_error(:unauthorized, "unauthorized") # passed the address block, failed authentication
      poll(credential)
      expect_error(:too_many_requests, "rate_limited")
    end

    it "counts an IPv6 client per /64, and an IPv4-mapped address as IPv4" do
      limit.times { |i| poll(wrong, from: "2001:db8:1:2::#{i + 1}") }
      poll(credential, from: "2001:db8:1:2:ffff::1") # same /64
      expect_error(:too_many_requests, "rate_limited")
      poll(credential, from: "2001:db8:1:3::1") # another /64
      expect(response).to have_http_status(:ok)
      limit.times { poll(wrong, from: "::ffff:192.0.2.20") }
      poll(credential, from: "192.0.2.21")
      expect(response).to have_http_status(:ok) # not one key for every mapped address
    end

    it "keeps a blocked address blocked while failures from many other addresses arrive (review of #211)" do
      small = AgentApi::RateLimiter.new(max_keys: 5)
      allow(AgentApi).to receive(:failed_auth_rate_limiter).and_return(small)
      limit.times { poll(wrong) }
      20.times do |i|
        poll(wrong, from: "198.51.100.#{i + 1}")
        poll(wrong) # the blocked address keeps trying
      end
      poll(credential)
      expect_error(:too_many_requests, "rate_limited")
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
