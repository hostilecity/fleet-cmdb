require "rails_helper"

# Report load shedding (#200, review of #208): AgentApi::ReportShedding, applied by Api::V1::AuthenticatedController
# (sheds_report_load) after the failed-authentication check and before authentication. FLEET_REPORT_MAX_IN_FLIGHT and
# FLEET_REPORT_RETRY_AFTER_SECONDS.
RSpec.describe AgentApi::ReportShedding do
  let(:settings) { AgentApi.config }

  around do |example|
    before = settings.report_shedding
    settings.report_shedding = { max_in_flight: 1, retry_after: 30 }
    example.run
  ensure
    settings.report_shedding = before
  end

  describe ".within_limit" do
    let(:gauge) { described_class::Gauge.new }

    it "runs the block with a slot taken, and frees it after, also when the block raises" do
      expect(described_class.within_limit(gauge:) { gauge.count }).to eq([ true, 1 ])
      expect(gauge.count).to eq(0)
      expect { described_class.within_limit(gauge:) { raise "boom" } }.to raise_error("boom")
      expect(gauge.count).to eq(0)
    end

    it "returns a Retry-After between retry_after and 1.5 times that when every slot is taken, without running the block" do
      gauge.enter(1)
      ran = false
      waits = Array.new(200) { |seed| described_class.within_limit(gauge:, random: Random.new(seed)) { ran = true } }
      expect(ran).to be(false)
      expect(waits.map(&:first)).to all(be(false))
      expect(waits.map(&:last)).to all(be_between(30, 45))
      expect(waits.map(&:last).uniq.size).to be > 10
    end

    it "is off with a limit of 0" do
      settings.report_shedding = { max_in_flight: 0, retry_after: 30 }
      gauge.enter(1_000)
      expect(described_class.within_limit(gauge:) { :ran }).to eq([ true, :ran ])
    end
  end

  describe "in the app", type: :request do
    let!(:enrolled) { enrolled_host }
    let(:credential) { enrolled.last }
    let(:gauge) { described_class::GAUGE }

    def inventory = inventory_example.merge("report_id" => SecureRandom.uuid)

    def heartbeat
      post_api("/api/v1/heartbeat", { schema_version: 1, agent_version: "0.1.0", hostname: "vm-01.example.lan", uptime_seconds: 42,
                                      agent_time: "2026-01-01T12:00:00Z" }, credential)
    end

    def statements_of
      statements = []
      callback = ->(*, payload) { statements << payload[:sql] unless payload[:name] == "SCHEMA" }
      ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { yield }
      statements
    end

    it "answers a report with 503 and Retry-After while the process is at its limit, with no database work, and keeps heartbeats" do
      gauge.enter(1)
      begin
        payload = inventory
        statements = statements_of { post_api("/api/v1/reports/inventory", payload, credential) }
        expect_error(:service_unavailable, "overloaded")
        expect(response.headers["Retry-After"].to_i).to be_between(30, 45)
        expect(statements).to be_empty # no authentication, no transaction
        heartbeat
        expect(response).to have_http_status(:ok)
      ensure
        gauge.leave
      end

      # The agent retries the same report later, and it is accepted.
      post_api("/api/v1/reports/inventory", payload, credential)
      expect(response).to have_http_status(:ok)
      expect(json).to eq("report_id" => payload["report_id"], "duplicate" => false)
      expect(gauge.count).to eq(0)
    end

    it "logs each shed request with its path and the count" do
      gauge.enter(1)
      log = captured_log { post_api("/api/v1/reports/packages", {}, credential) }
      expect(log).to match(%r{\[agent_api\] shed /api/v1/reports/packages: 1 reports in flight; retry after \d+s})
    ensure
      gauge.leave
    end

    it "counts nothing for an address the failed-authentication limit refuses: it gets 429, not a slot" do
      wrong = "fa_EXAMPLEunknownkey000.#{'x' * 43}"
      AgentApi.config.failed_auth_rate_limit[:to].times { post_api("/api/v1/reports/config", inventory, wrong) }
      allow(described_class).to receive(:within_limit).and_call_original
      post_api("/api/v1/reports/config", inventory, wrong)
      expect_error(:too_many_requests, "rate_limited")
      expect(described_class).not_to have_received(:within_limit)
    end

    it "sheds every report endpoint and nothing else, and serves no .json variant that could skip it" do
      gauge.enter(1)
      begin
        %w[inventory config packages].each do |type|
          post_api("/api/v1/reports/#{type}", inventory, credential)
          expect_error(:service_unavailable, "overloaded")
          post_api("/api/v1/reports/#{type}.json", inventory, credential)
          expect_error(:not_found, "not_found")
        end
        post_api("/api/v1/tasks/poll", { "schema_version" => 1, "agent_version" => "0.3.0" }, credential)
        expect(response).to have_http_status(:ok)
      ensure
        gauge.leave
      end
    end
  end

  describe "the settings at boot" do
    def boot_with(env)
      saved = env.keys.index_with { |key| ENV.fetch(key, nil) }
      env.each { |key, value| ENV[key] = value }
      settings.delete(:report_shedding)
      load Rails.root.join("config/initializers/agent_api.rb")
      settings.report_shedding
    ensure
      saved.each { |key, value| ENV[key] = value }
    end

    it "is off with a 30 s Retry-After by default, and takes whole numbers within the bounds" do
      expect(boot_with("FLEET_REPORT_MAX_IN_FLIGHT" => nil, "FLEET_REPORT_RETRY_AFTER_SECONDS" => nil)).to eq(max_in_flight: 0, retry_after: 30)
      expect(boot_with("FLEET_REPORT_MAX_IN_FLIGHT" => "2", "FLEET_REPORT_RETRY_AFTER_SECONDS" => "600")).to eq(max_in_flight: 2, retry_after: 600)
    end

    it "stops the server at boot, naming the setting, for anything else" do
      [ "", "-1", "10001", "1.5", "two" ].each do |value|
        expect { boot_with("FLEET_REPORT_MAX_IN_FLIGHT" => value, "FLEET_REPORT_RETRY_AFTER_SECONDS" => nil) }
          .to raise_error(RuntimeError, "FLEET_REPORT_MAX_IN_FLIGHT must be a whole number from 0 (off) to 10000 (got #{value.inspect})")
      end
      [ "", "0", "601", "3600", "30s" ].each do |value|
        expect { boot_with("FLEET_REPORT_MAX_IN_FLIGHT" => nil, "FLEET_REPORT_RETRY_AFTER_SECONDS" => value) }
          .to raise_error(RuntimeError, "FLEET_REPORT_RETRY_AFTER_SECONDS must be a whole number of seconds from 1 to 600 (got #{value.inspect})")
      end
    end
  end
end
