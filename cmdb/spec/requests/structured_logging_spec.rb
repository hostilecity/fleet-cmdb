require "rails_helper"

# Structured, traceable, credential-free logs (NFR-4, NFR-1, P1-S11, P1-S12).
RSpec.describe "Structured logging", type: :request do
  let(:io) { StringIO.new }
  let(:structured) { ActiveSupport::TaggedLogging.logger(io, formatter: StructuredLogFormatter.new) }
  let(:host_and_credential) { enrolled_host }
  let(:host) { host_and_credential.first }
  let(:credential) { host_and_credential.last }

  around do |example|
    Rails.configuration.x.logging.structured = true
    Rails.logger.broadcast_to(structured)
    example.run
  ensure
    Rails.logger.stop_broadcasting_to(structured)
    Rails.configuration.x.logging.structured = nil
  end

  def clear_log
    io.truncate(0)
    io.rewind
  end

  def lines = io.string.lines.map { |line| JSON.parse(line) }

  def request_line = lines.find { |line| line["event"] == "request" }

  def send_report(payload, headers: {})
    post "/api/v1/reports/inventory", params: payload.to_json, headers: api_headers(credential).merge(headers)
  end

  let(:report) { inventory_example("full").merge("report_id" => SecureRandom.uuid) }

  describe "an inventory report" do
    before do
      host!(agent_host)
      host_and_credential # enrolled before the request, so only the request is measured
      clear_log
    end

    it "logs JSON lines that carry the request id, host id, and report id, and one line with the duration" do
      send_report(report)

      expect(response).to have_http_status(:ok)
      expect(lines).not_to be_empty
      expect(lines).to all(include("time" => a_string_matching(/\A\d{4}-\d\d-\d\dT[\d:.]+Z\z/), "level" => a_kind_of(String), "message" => a_kind_of(String)))
      request_id = response.headers["X-Request-Id"]
      expect(lines.map { |line| line["request_id"] }.uniq).to eq([ request_id ])

      done = request_line
      expect(done).to include("message" => "request completed", "method" => "POST", "controller" => "Api::V1::InventoryReportsController",
                              "action" => "create", "status" => 200, "host_id" => host.id, "report_id" => report["report_id"])
      expect(done["duration_ms"]).to be_a(Numeric).and be >= 0
    end

    it "traces a report by the request id the agent sent, which the response returns" do
      send_report(report, headers: { "X-Request-Id" => "agent-trace-0001" })

      expect(response.headers["X-Request-Id"]).to eq("agent-trace-0001")
      expect(lines.map { |line| line["request_id"] }.uniq).to eq([ "agent-trace-0001" ])
      expect(request_line).to include("report_id" => report["report_id"])
    end

    it "returns the request id in error envelopes, matching the log" do
      post "/api/v1/reports/inventory", params: "{}", headers: api_headers(credential)

      expect_error(400, "validation_failed")
      expect(request_line).to include("request_id" => json.dig("error", "request_id"), "status" => 400, "host_id" => host.id)
      expect(request_line).not_to have_key("report_id") # the body was not a valid report
    end

    it "logs a refused request without a host id, and the request id of the refusal" do
      post "/api/v1/heartbeat", params: "{}", headers: api_headers("not-a-credential")

      expect_error(401, "unauthorized")
      expect(request_line).to include("status" => 401, "request_id" => response.headers["X-Request-Id"])
      expect(request_line).not_to have_key("host_id")
    end

    it "keeps the host and report ids of one request off the next one" do
      send_report(report)
      clear_log

      post "/api/v1/heartbeat", params: "{}", headers: api_headers("not-a-credential")

      expect(lines.map { |line| line.slice("host_id", "report_id") }.uniq).to eq([ {} ])
    end

    it "never writes the credential, the authorization header, or the report body to the log" do
      send_report(report.merge("hostname" => "vm-01.example.lan"))
      post "/api/v1/heartbeat", params: { token: "t0ps3cret" }.to_json, headers: api_headers(credential)

      expect(io.string).not_to include(credential.to_s)
      expect(io.string).not_to match(/authorization|bearer/i)
      expect(io.string).not_to include("t0ps3cret")
      # Debug lines (SQL) are not written in production, where the level is info.
      expect(lines.reject { |line| line["level"] == "DEBUG" }.map { |line| line["message"] }.join).not_to include(report["boot_id"].to_s)
    end
  end

  describe "a dashboard request" do
    it "logs the request id and duration, no query string of its own, and filters secret-like parameters" do
      sign_in_operator
      clear_log

      get "/audit", params: { actor: "alice", password: "pw-leak-1", token: "tok-leak-2", authorization: "Bearer auth-leak-3", secret: "sec-leak-4", credential: "cred-leak-5" }

      expect(request_line).to include("controller" => "AuditEntriesController", "action" => "index", "method" => "GET")
      expect(io.string).to include("[FILTERED]")
      %w[pw-leak-1 tok-leak-2 auth-leak-3 sec-leak-4 cred-leak-5].each { |value| expect(io.string).not_to include(value), "#{value} reached the log" }
      expect(io.string).to include("password=[FILTERED]") # Rails filters the query string in its own request line
      expect(request_line.values.join(" ")).not_to include("actor=alice") # and our request line has no query string at all
    end

    it "does not log the sign-in session cookie" do
      sign_in_operator
      cookie = cookies["_fleet_cmdb_session"]
      clear_log

      get "/"

      expect(cookie).to be_present
      expect(io.string).not_to include(cookie.to_s)
    end
  end

  describe "when structured request lines are off" do
    it "adds no request line (development and test)" do
      Rails.configuration.x.logging.structured = nil
      host!(agent_host)
      host_and_credential
      clear_log

      send_report(report)

      expect(request_line).to be_nil
    end
  end

  describe StructuredLogFormatter do
    subject(:formatter) { described_class.new }

    def entry(message, severity: "INFO") = JSON.parse(formatter.call(severity, Time.utc(2026, 11, 1, 12, 0, 0, 123_000), nil, message))

    it "writes one JSON object per line with the time, level, and message" do
      line = formatter.call("WARN", Time.utc(2026, 11, 1, 12, 0, 0, 123_000), nil, "disk almost full")

      expect(line).to end_with("\n")
      expect(line.count("\n")).to eq(1)
      expect(JSON.parse(line)).to eq("time" => "2026-11-01T12:00:00.123Z", "level" => "WARN", "message" => "disk almost full")
    end

    it "keeps a newline or control character in a value from forging another log line" do
      forged = "ok\n{\"level\":\"FATAL\",\"message\":\"forged\"}\u0007"
      line = formatter.call("INFO", Time.now, nil, "hostname #{forged}")

      expect(line.count("\n")).to eq(1)
      expect(JSON.parse(line)["message"]).to eq("hostname #{forged}")
    end

    it "describes exceptions and other objects, repairs invalid bytes, and truncates very long messages" do
      expect(entry(ArgumentError.new("bad"))["message"]).to eq("ArgumentError: bad")
      expect(entry({ a: 1 })["message"]).to eq({ a: 1 }.inspect)
      expect(entry("bad \xFF byte")["message"]).to eq("bad � byte")
      expect(entry("x" * 20_000)["message"].size).to eq(StructuredLogFormatter::MESSAGE_LIMIT)
    end

    it "adds fields for the block only, and nested blocks add to the outer ones" do
      inner = nil
      outer = described_class.with_fields(a: 1) do
        described_class.with_fields(b: 2) { inner = entry("in") }
        entry("out")
      end

      expect(inner).to include("a" => 1, "b" => 2)
      expect(outer).to include("a" => 1).and(satisfy { |line| !line.key?("b") })
      expect(entry("after").keys).to eq(%w[time level message])
    end

    it "takes the request, host, and report ids from Current, and leaves out those that are not known" do
      Current.request_id = "req-1"
      Current.host_id = 7

      expect(entry("x")).to include("request_id" => "req-1", "host_id" => 7)
      expect(entry("x")).not_to have_key("report_id")
    ensure
      Current.reset
    end
  end
end
