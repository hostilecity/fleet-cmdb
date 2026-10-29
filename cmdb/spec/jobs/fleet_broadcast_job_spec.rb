require "rails_helper"

# Live fleet updates (P1-D05): what is broadcast, and when.
RSpec.describe FleetBroadcastJob, type: :job do
  include ActiveJob::TestHelper

  let(:host) { enrolled_host(name: "Media server").first }

  def broadcasts = ActionCable.server.pubsub.broadcasts(FleetBroadcast::STREAM)

  def streams(message) = Nokogiri::HTML.fragment(JSON.parse(message)).css("turbo-stream")

  before { ActionCable.server.pubsub.clear }

  describe "#perform" do
    # A page refresh, not targeted replacements: each open page re-requests itself with its own filters and
    # sort, so list membership, order, counts, and empty states cannot drift (review of #53).
    it "sends one Turbo page refresh to the fleet stream, with no host data in it" do
      host.edit!({ name: %(<script>alert("x")</script>) }, actor: Audit::SYSTEM)
      described_class.perform_now([ host.id ])
      expect(broadcasts.size).to eq(1)
      parts = streams(broadcasts.first)
      expect(parts.map { |s| s["action"] }).to eq([ "refresh" ])
      expect(JSON.parse(broadcasts.first)).not_to include("alert")
    end

    it "refreshes for a retired host too, so its open detail page shows the new state" do
      host.retire!(actor: Audit::SYSTEM)
      described_class.perform_now([ host.id ])
      expect(streams(broadcasts.last).map { |s| s["action"] }).to eq([ "refresh" ])
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

    it "enqueues when a token is issued without a state change: pre-registering, or a new token for a pending host (review of #63)" do
      registered, = Enrollment::RegisterHost.call({ name: "Lab sandbox", hostname: "vm-06.example.lan" }, actor: Audit::SYSTEM)
      expect(enqueued_ids).to eq([ registered.id ])
      clear_enqueued_jobs
      Enrollment::IssueToken.call(host: registered, actor: Audit::SYSTEM)
      expect(enqueued_ids).to eq([ registered.id ])
      clear_enqueued_jobs
      Enrollment::IssueToken.call(host:, actor: Audit::SYSTEM) # active -> pending: the transition's one refresh
      expect(enqueued_ids).to eq([ host.id ])
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
