require "rails_helper"

# The report_request heartbeat directive end to end (P2-S03, FR-2.1, DEC-13, DEC-20): an operator's request is
# on the next heartbeat, and gone once a report of that type, collected after the request, arrives through the
# report endpoint (InventoryRecorder, PackageRecorder, ConfigRecorder).
RSpec.describe "Report requests in the agent API", type: :request do
  let(:operator) { create(:operator) }
  let!(:enrolled) { enrolled_host }
  let(:host) { enrolled.first }
  let(:credential) { enrolled.last }

  # Report type => endpoint, request schema, and the contract example sent.
  let(:endpoints) do
    { "config" => [ "/api/v1/reports/config", "config.request", "typical" ],
      "inventory" => [ "/api/v1/reports/inventory", "inventory.request", "full" ],
      "packages" => [ "/api/v1/reports/packages", "packages.request", "dpkg" ] }
  end

  def heartbeat(agent_time: Time.current)
    post_api("/api/v1/heartbeat", { schema_version: 1, agent_version: "0.1.0", hostname: "vm-01.example.lan", uptime_seconds: 42,
                                    agent_time: agent_time.utc.iso8601 }, credential)
    expect(response).to have_http_status(:ok)
    expect(ApiContract.errors("heartbeat.response", "v1", json)).to eq([])
    json["directives"]
  end

  def send_report(type, collected_at:, report_id: SecureRandom.uuid)
    path, schema, example = endpoints.fetch(type)
    post_api(path, ApiContract.example(schema, example).merge("report_id" => report_id, "collected_at" => collected_at.utc.iso8601), credential)
    expect(response).to have_http_status(:ok)
  end

  def request_reports(types) = ReportRequests.request!(host:, types:, actor: operator)

  def report_request_writes(&)
    writes = []
    callback = ->(*, payload) { writes << payload[:sql] if payload[:sql].match?(/\A\s*(INSERT|UPDATE|DELETE)[^;]*report_requests/i) }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record", &)
    writes.size
  end

  it "puts an operator's request on the next heartbeat, and keeps it there until a report answers it" do
    heartbeat
    expect(heartbeat).to eq({})
    request_reports(%w[config packages])
    expect(heartbeat).to eq("report_request" => { "types" => %w[config packages] })
    expect(heartbeat).to eq("report_request" => { "types" => %w[config packages] }) # a lost response loses nothing
    travel 1.second
    send_report("config", collected_at: Time.current)
    expect(heartbeat).to eq("report_request" => { "types" => %w[packages] })
    send_report("packages", collected_at: Time.current)
    expect(heartbeat).to eq({})
    expect(host.report_requests.pluck(:state)).to all(eq("satisfied"))
  end

  ReportRequest::TYPES.each do |type|
    it "clears a #{type} request with a #{type} report collected after it, and not with a retried older one" do
      old_report = SecureRandom.uuid
      send_report(type, collected_at: 1.minute.ago, report_id: old_report)
      request_reports([ type ])
      travel 1.second
      send_report(type, collected_at: 2.minutes.ago) # collected before the request, delivered after it
      send_report(type, collected_at: Time.current, report_id: old_report) # a duplicate changes nothing
      expect(heartbeat).to eq("report_request" => { "types" => [ type ] })
      report_id = SecureRandom.uuid
      send_report(type, collected_at: Time.current, report_id:)
      expect(host.report_requests.sole).to have_attributes(state: "satisfied", satisfied_by_report_id: report_id)
      expect(heartbeat).to eq({})
    end
  end

  it "clears a request with a fresh report from an agent whose clock is far behind the server's" do
    agent_clock = Time.utc(2026, 1, 1, 12, 0, 0) # the contract examples' time, months before the server's
    heartbeat(agent_time: agent_clock)
    request_reports(%w[inventory])
    travel 5.seconds
    send_report("inventory", collected_at: agent_clock + 5.seconds)
    expect(host.report_requests.sole.state).to eq("satisfied")
  end

  it "leaves an agent that ignores the directive unaffected: its heartbeats succeed, and the request expires visibly" do
    request_reports(ReportRequest::TYPES)
    3.times { expect(heartbeat).to eq("report_request" => { "types" => ReportRequest::TYPES }) }
    expect(host.reload.liveness_status).to eq("online")
    travel(61.minutes) do
      expect(heartbeat).to eq({}) # no longer asked, even before the job runs
      ReportRequestExpiryJob.perform_now
    end
    expect(host.report_requests.map { |r| [ r.state, r.expired_at.present? ] }.uniq).to eq([ [ "expired", true ] ])
  end

  it "costs a heartbeat with nothing outstanding no write, and one write the first time it carries a request" do
    heartbeat
    expect(report_request_writes { heartbeat }).to eq(0)
    request_reports(%w[config])
    expect(report_request_writes { heartbeat }).to eq(1) # sent_at
    expect(report_request_writes { heartbeat }).to eq(0)
  end
end
