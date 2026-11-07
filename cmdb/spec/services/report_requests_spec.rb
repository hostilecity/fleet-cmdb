require "rails_helper"

# On-demand report requests (P2-S03, FR-2.1, DEC-13): recording, rate limiting, the heartbeat directive,
# clearing by a report collected after the request (with the agent's clock skew), and expiry.
RSpec.describe ReportRequests do
  let(:operator) { create(:operator) }
  let!(:enrolled) { enrolled_host }
  let(:host) { enrolled.first }
  let(:now) { Time.utc(2026, 11, 6, 12, 0, 0) }

  def request(types = ReportRequest::TYPES, at: now, as: operator) = described_class.request!(host:, types:, actor: as, now: at)

  def directive(at: now) = Host.transaction { described_class.directive_for(host_id: host.id, now: at) }

  # A report as the recorders see it: only its id and the agent's collection time matter here.
  def report(collected_at) = Struct.new(:report_id, :collected_at).new(SecureRandom.uuid, collected_at)

  def satisfy(type, collected_at, at: now) = described_class.satisfy!(host: host.reload, report_type: type, report: report(collected_at), now: at)

  describe ".request!" do
    it "records one pending request per type with the operator and the server time, and audits it once" do
      result = request(%w[packages config])
      expect(result).to have_attributes(requested: %w[config packages], outstanding: [], rate_limited: [], retry_at: nil)
      expect(host.report_requests.order(:report_type).map { |r| [ r.report_type, r.state, r.requested_by, r.requested_at, r.expires_at ] })
        .to eq([ [ "config", "pending", operator, now, now + 1.hour ], [ "packages", "pending", operator, now, now + 1.hour ] ])
      entry = AuditEntry.for_target(host).where(action: Audit::Actions::HOST_REPORT_REQUESTED).sole
      expect([ entry.actor_type, entry.actor_id ]).to eq([ "operator", operator.id ])
      expect(entry.changeset).to eq("report_types" => [ nil, %w[config packages] ])
    end

    it "rate limits a repeat request for a type within five minutes, whatever happened to the first, and writes nothing" do
      request(%w[config])
      satisfy("config", now + 1.second, at: now + 2.seconds)
      expect do
        result = request(%w[config], at: now + 4.minutes)
        expect(result).to have_attributes(requested: [], rate_limited: %w[config], retry_at: now + 5.minutes)
      end.not_to(change { [ ReportRequest.count, AuditEntry.count ] })
      expect(request(%w[config], at: now + 5.minutes + 1.second).requested).to eq(%w[config])
    end

    it "limits each type on its own, so a request can be partly limited" do
      request(%w[config])
      result = request(ReportRequest::TYPES, at: now + 1.minute)
      expect(result).to have_attributes(requested: %w[inventory packages], rate_limited: %w[config], retry_at: now + 5.minutes)
      expect(AuditEntry.where(action: Audit::Actions::HOST_REPORT_REQUESTED).last.changeset["report_types"]).to eq([ nil, %w[inventory packages] ])
    end

    it "leaves a request that is still pending after the cooldown as it is, adding nothing" do
      request(%w[inventory])
      expect { expect(request(%w[inventory], at: now + 10.minutes).outstanding).to eq(%w[inventory]) }.not_to change(ReportRequest, :count)
      expect(host.report_requests.sole.requested_at).to eq(now)
    end

    it "expires a pending request past its expiry so a new one can be made" do
      request(%w[config])
      later = now + 61.minutes
      expect(request(%w[config], at: later).requested).to eq(%w[config])
      expect(host.report_requests.order(:id).map { |r| [ r.state, r.expired_at ] }).to eq([ [ "expired", later ], [ "pending", nil ] ])
    end

    it "ignores unknown types and refuses a request with no known type" do
      expect(request(%w[config bogus]).requested).to eq(%w[config])
      expect { request(%w[bogus]) }.to raise_error(ReportRequests::NoTypes)
      expect { request(nil) }.to raise_error(ReportRequests::NoTypes)
    end

    it "refuses a host that is not active, whose agent could never be asked" do
      host.revoke!(actor: Audit::SYSTEM)
      expect { request }.to raise_error(ReportRequests::NotActive)
      expect(ReportRequest.count).to eq(0)
    end

    it "allows only one pending request per host and type, in the database too" do
      request(%w[config])
      refused = ->(&write) { ReportRequest.transaction(requires_new: true) { write.call } }
      expect do
        refused.call { ReportRequest.insert!({ host_id: host.id, report_type: "config", requested_by_id: operator.id, requested_at: now, expires_at: now + 1.hour }) }
      end.to raise_error(ActiveRecord::RecordNotUnique)
      expect { refused.call { ReportRequest.where(host:).update_all(state: "satisfied") } }
        .to raise_error(ActiveRecord::StatementInvalid, /report_requests_satisfied_matches_state/)
      expect { refused.call { ReportRequest.where(host:).update_all(report_type: "logs") } }.to raise_error(ActiveRecord::StatementInvalid, /report_requests_type_valid/)
    end
  end

  describe ".directive_for" do
    it "is nil when nothing is outstanding, and lists the outstanding types in a fixed order" do
      expect(directive).to be_nil
      request(%w[packages inventory])
      expect(directive).to eq(types: %w[inventory packages])
    end

    it "records when a heartbeat first carried each request, and keeps sending it until it ends" do
      request(%w[config])
      directive(at: now + 1.minute)
      directive(at: now + 2.minutes)
      expect(host.report_requests.sole.sent_at).to eq(now + 1.minute)
      expect(directive(at: now + 3.minutes)).to eq(types: %w[config])
    end

    it "stops sending a request once it is satisfied or past its expiry, even before the expiry job marks it" do
      request(%w[config inventory])
      satisfy("config", now + 30.seconds)
      expect(directive(at: now + 1.minute)).to eq(types: %w[inventory])
      expect(directive(at: now + 1.hour)).to be_nil
      expect(host.report_requests.find_by(report_type: "inventory").state).to eq("pending")
    end

    it "only lists the host's own requests" do
      other, = enrolled_host
      described_class.request!(host: other, types: %w[config], actor: operator, now:)
      expect(directive).to be_nil
    end
  end

  describe ".satisfy!" do
    before { request(%w[config packages]) }

    it "clears the pending request of the report's type with a report collected after it, recording the report" do
      collected = report(now + 1.minute)
      expect(described_class.satisfy!(host:, report_type: "config", report: collected, now: now + 2.minutes)).to eq(1)
      config = host.report_requests.find_by!(report_type: "config")
      expect(config).to have_attributes(state: "satisfied", satisfied_at: now + 2.minutes, satisfied_by_report_id: collected.report_id)
      expect(host.report_requests.find_by!(report_type: "packages").state).to eq("pending")
    end

    it "does not clear a request with a report collected before it, or at the same instant" do
      expect(satisfy("config", now - 1.second)).to eq(0)
      expect(satisfy("config", now)).to eq(0)
      expect(host.report_requests.pending.count).to eq(2)
    end

    it "moves the agent's collection time onto the server clock with the offset the last heartbeat measured" do
      # The agent's clock is ten minutes behind: compared directly, a fresh report would look older than the request.
      host.update_columns(last_seen_at: now - 1.minute, agent_reported_at: now - 11.minutes)
      expect(satisfy("config", now - 9.minutes)).to eq(1) # collected one minute after the request, on the server clock
      # Ten minutes ahead: compared directly, a report collected before the request would clear it.
      host.update_columns(last_seen_at: now - 1.minute, agent_reported_at: now + 9.minutes)
      expect(satisfy("packages", now + 9.minutes)).to eq(0) # collected one minute before the request
      expect(satisfy("packages", now + 10.minutes + 1.second)).to eq(1)
    end

    it "compares the times directly for a host that has not sent a heartbeat" do
      host.update_columns(last_seen_at: nil, agent_reported_at: nil)
      expect(satisfy("config", now + 1.second)).to eq(1)
    end

    it "still clears a request past its expiry that the expiry job has not marked yet" do
      expect(satisfy("config", now + 70.minutes, at: now + 70.minutes)).to eq(1)
    end

    it "leaves an expired request expired" do
      described_class.expire!(now: now + 2.hours)
      expect(satisfy("config", now + 1.minute)).to eq(0)
      expect(host.report_requests.pluck(:state)).to all(eq("expired"))
    end
  end

  describe ".expire!" do
    it "marks pending requests past their expiry as expired with the time, keeping them, and leaves the rest" do
      request(%w[config inventory])
      satisfy("inventory", now + 1.minute)
      other, = enrolled_host
      described_class.request!(host: other, types: %w[config], actor: operator, now: now + 30.minutes)

      expect(described_class.expire!(now: now + 1.hour)).to eq(1)
      expect(ReportRequest.order(:id).map { |r| [ r.report_type, r.state, r.expired_at ] })
        .to eq([ [ "config", "expired", now + 1.hour ], [ "inventory", "satisfied", nil ], [ "config", "pending", nil ] ])
      expect(host.report_requests.find_by!(report_type: "config").display_state(now + 2.hours)).to eq("expired")
    end

    it "runs from the recurring job, every minute in every environment that runs jobs" do
      request(%w[config])
      travel_to(now + 2.hours) { ReportRequestExpiryJob.perform_now }
      expect(host.report_requests.sole.state).to eq("expired")
      recurring = YAML.load_file(Rails.root.join("config/recurring.yml"), aliases: true)
      %w[production development].each do |env|
        expect(recurring.fetch(env)["report_request_expiry"]).to eq("class" => "ReportRequestExpiryJob", "schedule" => "every minute")
      end
    end
  end

  describe "ReportRequest#display_state" do
    it "reads a pending request past its expiry as expired" do
      request(%w[config])
      pending = host.report_requests.sole
      expect([ pending.display_state(now + 59.minutes), pending.display_state(now + 1.hour) ]).to eq(%w[pending expired])
    end
  end
end
