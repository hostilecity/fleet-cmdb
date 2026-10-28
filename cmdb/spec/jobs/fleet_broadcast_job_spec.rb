require "rails_helper"

# Live fleet updates (P1-D05): what is broadcast, and when.
RSpec.describe FleetBroadcastJob, type: :job do
  include ActiveJob::TestHelper

  let(:host) { enrolled_host(name: "Media server").first }

  def broadcasts = ActionCable.server.pubsub.broadcasts(FleetBroadcast::STREAM)

  def streams(message) = Nokogiri::HTML.fragment(JSON.parse(message)).css("turbo-stream")

  before { ActionCable.server.pubsub.clear }

  describe "#perform" do
    it "replaces the row, the host's status header, and the counts in one message" do
      record_heartbeat(host)
      described_class.perform_now([ host.id ])
      expect(broadcasts.size).to eq(1)
      parts = streams(broadcasts.first)
      expect(parts.map { |s| [ s["action"], s["target"] ] }).to eq([
        [ "replace", "row_host_#{host.id}" ], [ "replace", "status_host_#{host.id}" ], %w[replace fleet_counts]
      ])
      row = parts[0].at_css("template").children
      expect(row.at_css("tr")["id"]).to eq("row_host_#{host.id}")
      expect(row.at_css(".lamp").text).to eq("Online")
      expect(parts[2].css(".count").map(&:text)).to eq(%w[1 0 0 0 0 0])
    end

    it "removes a retired host's row" do
      host.retire!(actor: Audit::SYSTEM)
      described_class.perform_now([ host.id ])
      expect(streams(broadcasts.last).map { |s| [ s["action"], s["target"] ] }).to eq([ [ "remove", "row_host_#{host.id}" ], %w[replace fleet_counts] ])
    end

    it "escapes host text" do
      host.edit!({ name: %(<script>alert("x")</script>) }, actor: Audit::SYSTEM)
      described_class.perform_now([ host.id ])
      html = JSON.parse(broadcasts.last)
      expect(html).not_to include("<script>alert")
      expect(html).to include("&lt;script&gt;alert")
    end
  end

  describe "enqueueing (after commit only)" do
    def enqueued_ids = enqueued_jobs.select { |j| j["job_class"] == "FleetBroadcastJob" }.flat_map { |j| j["arguments"].first }

    before do
      host
      clear_enqueued_jobs
    end

    it "enqueues when a heartbeat changes the status, and not for an ordinary heartbeat" do
      record_heartbeat(host)
      expect(enqueued_ids).to eq([ host.id ])
      clear_enqueued_jobs
      record_heartbeat(host)
      expect(enqueued_ids).to eq([])
    end

    it "enqueues once for all hosts an evaluation moves" do
      other = enrolled_host.first
      [ host, other ].each { |h| record_heartbeat(h) }
      clear_enqueued_jobs
      Liveness.evaluate!(now: 20.minutes.from_now)
      expect(enqueued_jobs.count { |j| j["job_class"] == "FleetBroadcastJob" }).to eq(1)
      expect(enqueued_ids).to contain_exactly(host.id, other.id)
      clear_enqueued_jobs
      Liveness.evaluate!(now: 20.minutes.from_now)
      expect(enqueued_ids).to eq([])
    end

    it "enqueues on enrollment transitions and edits" do
      host.revoke!(actor: Audit::SYSTEM)
      host.edit!({ name: "Renamed" }, actor: Audit::SYSTEM)
      host.edit!({ name: "Renamed" }, actor: Audit::SYSTEM) # no change, no broadcast
      expect(enqueued_ids).to eq([ host.id, host.id ])
    end

    it "enqueues when the first inventory arrives, so the row gains its operating system" do
      record_inventory(host)
      record_inventory(host)
      expect(enqueued_ids).to eq([ host.id ])
    end

    it "waits for the outermost transaction to commit, and enqueues nothing on rollback" do
      Host.transaction do
        host.revoke!(actor: Audit::SYSTEM)
        expect(enqueued_ids).to eq([])
        raise ActiveRecord::Rollback
      end
      expect(enqueued_ids).to eq([])
      expect(host.reload.enrollment_state).to eq("active")

      Host.transaction do
        host.revoke!(actor: Audit::SYSTEM)
        expect(enqueued_ids).to eq([])
      end
      expect(enqueued_ids).to eq([ host.id ])
    end
  end
end
