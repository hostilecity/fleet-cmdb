require "rails_helper"

# On-demand report requests (P2-S03, FR-2.1, DEC-13): recording, rate limiting, the heartbeat directive,
# clearing by a report the agent collected after a heartbeat delivered the request (on the agent's clock, so
# clock skew and latency cannot clear it early), and expiry.
RSpec.describe ReportRequests do
  let(:operator) { create(:operator) }
  let!(:enrolled) { enrolled_host }
  let(:host) { enrolled.first }
  let(:now) { Time.utc(2026, 11, 6, 12, 0, 0) }

  def request(types = ReportRequest::TYPES, at: now, as: operator) = described_class.request!(host:, types:, actor: as, now: at)

  # A heartbeat recorded by the server at `at`, which the agent stamped `agent_time` (its clock).
  def directive(at: now, agent_time: at) = Host.transaction { described_class.directive_for(host_id: host.id, agent_time:, now: at) }

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
      directive(at: now + 1.second)
      satisfy("config", now + 2.seconds, at: now + 3.seconds)
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
      expect { refused.call { ReportRequest.where(host:).update_all(state: "satisfied", sent_at: now, delivered_agent_time: now) } }
        .to raise_error(ActiveRecord::StatementInvalid, /report_requests_satisfied_matches_state/)
      expect { refused.call { ReportRequest.where(host:).update_all(sent_at: now) } }.to raise_error(ActiveRecord::StatementInvalid, /report_requests_delivery_complete/)
      expect { refused.call { ReportRequest.where(host:).update_all(report_type: "logs") } }.to raise_error(ActiveRecord::StatementInvalid, /report_requests_type_valid/)
    end
  end

  describe ".directive_for" do
    it "is nil when nothing is outstanding, and lists the outstanding types in a fixed order" do
      expect(directive).to be_nil
      request(%w[packages inventory])
      expect(directive).to eq(types: %w[inventory packages])
    end

    it "records when a heartbeat first carried each request, on both clocks, and keeps sending it until it ends" do
      request(%w[config])
      directive(at: now + 1.minute, agent_time: now - 3.hours)
      directive(at: now + 2.minutes, agent_time: now - 2.hours)
      expect(host.report_requests.sole).to have_attributes(sent_at: now + 1.minute, delivered_agent_time: now - 3.hours)
      expect(directive(at: now + 3.minutes)).to eq(types: %w[config])
    end

    it "stops sending a request once it is satisfied or past its expiry, even before the expiry job marks it" do
      request(%w[config inventory])
      directive(at: now + 10.seconds)
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

    it "clears the pending request of the report's type with a report collected after delivery, recording the report" do
      directive(at: now + 30.seconds)
      collected = report(now + 1.minute)
      expect(described_class.satisfy!(host:, report_type: "config", report: collected, now: now + 2.minutes)).to eq(1)
      config = host.report_requests.find_by!(report_type: "config")
      expect(config).to have_attributes(state: "satisfied", satisfied_at: now + 2.minutes, satisfied_by_report_id: collected.report_id)
      expect(host.report_requests.find_by!(report_type: "packages").state).to eq("pending")
    end

    it "leaves a request no heartbeat has delivered pending, however fresh the report looks" do
      expect(satisfy("config", now + 10.minutes, at: now + 10.minutes)).to eq(0)
      expect(host.report_requests.pending.count).to eq(2)
    end

    it "leaves the request pending with a report collected before delivery or at the same instant" do
      directive(at: now + 1.minute)
      expect(satisfy("config", now + 30.seconds, at: now + 2.minutes)).to eq(0) # retried after delivery, collected before it
      expect(satisfy("config", now + 1.minute, at: now + 2.minutes)).to eq(0)
      expect(host.report_requests.pending.count).to eq(2)
    end

    it "does not let a delayed heartbeat make a report collected before the request clear it (review of #111)" do
      # Synchronised clocks. A heartbeat stamped 12:00:00 is recorded at 12:00:05 (network or lock delay),
      # carrying nothing; the request is made at 12:00:06; a report collected at 12:00:03 is accepted on retry.
      host.update_columns(last_seen_at: now + 5.seconds, agent_reported_at: now)
      ReportRequest.where(host:).update_all(requested_at: now + 6.seconds)
      expect(satisfy("config", now + 3.seconds, at: now + 7.seconds)).to eq(0)
      # The next heartbeat delivers it; the old report retried again still does not count.
      directive(at: now + 65.seconds, agent_time: now + 60.seconds)
      expect(satisfy("config", now + 3.seconds, at: now + 66.seconds)).to eq(0)
      expect(satisfy("config", now + 61.seconds, at: now + 67.seconds)).to eq(1)
    end

    it "compares on the agent's own clock, so an agent clock far ahead or far behind the server's does not matter" do
      ahead = now + 3.hours
      directive(at: now + 1.minute, agent_time: ahead + 1.minute)
      expect(satisfy("config", ahead + 30.seconds, at: now + 2.minutes)).to eq(0) # before delivery on the agent's clock
      expect(satisfy("config", ahead + 2.minutes, at: now + 2.minutes)).to eq(1)
      behind = Time.utc(2001, 1, 1)
      ReportRequest.where(host:, report_type: "packages").update_all(delivered_agent_time: behind + 1.minute)
      expect(satisfy("packages", behind + 30.seconds)).to eq(0)
      expect(satisfy("packages", behind + 2.minutes)).to eq(1)
    end

    it "still clears a request past its expiry that the expiry job has not marked yet" do
      directive(at: now + 1.minute)
      expect(satisfy("config", now + 70.minutes, at: now + 70.minutes)).to eq(1)
    end

    it "leaves an expired request expired" do
      directive(at: now + 1.minute)
      described_class.expire!(now: now + 2.hours)
      expect(satisfy("config", now + 90.minutes)).to eq(0)
      expect(host.report_requests.pluck(:state)).to all(eq("expired"))
    end

    it "is refused by the database for a request no heartbeat delivered" do
      expect do
        ReportRequest.where(host:).update_all(state: "satisfied", satisfied_at: now, satisfied_by_report_id: SecureRandom.uuid)
      end.to raise_error(ActiveRecord::StatementInvalid, /report_requests_satisfied_after_delivery/)
    end
  end

  describe ".expire!" do
    it "marks pending requests past their expiry as expired with the time, keeping them, and leaves the rest" do
      request(%w[config inventory])
      directive(at: now + 10.seconds)
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

  describe ".availability (the request buttons, P2-D02)" do
    def states(at) = described_class.availability(host: host.reload, now: at).transform_values { |a| [ a.state, a.retry_at ] }

    it "is ready for every type before any request, and inactive on a host that is not active" do
      expect(states(now)).to eq("config" => [ :ready, nil ], "inventory" => [ :ready, nil ], "packages" => [ :ready, nil ])
      host.revoke!(actor: Audit::SYSTEM)
      expect(states(now).values.map(&:first).uniq).to eq([ :inactive ])
    end

    it "is pending while a request is outstanding, rate limited for five minutes after it ended, then ready" do
      request(%w[config])
      expect(states(now + 1.minute)["config"]).to eq([ :pending, nil ])
      directive(at: now + 1.minute)
      satisfy("config", now + 2.minutes, at: now + 2.minutes)
      expect(states(now + 3.minutes)["config"]).to eq([ :rate_limited, now + 5.minutes ])
      expect(states(now + 5.minutes)["config"]).to eq([ :ready, nil ])
      expect(described_class.availability(host:, now:)["config"].latest).to have_attributes(state: "satisfied", requested_by: operator)
    end

    it "is pending past the cool-down until the request expires, as request! leaves it outstanding" do
      request(%w[packages])
      expect(states(now + 30.minutes)["packages"]).to eq([ :pending, nil ])
      expect(states(now + 1.hour)["packages"]).to eq([ :ready, nil ])
      expect(states(now + 30.minutes)["inventory"]).to eq([ :ready, nil ])
    end

    it "reads the newest request of each type" do
      request(%w[config])
      described_class.expire!(now: now + 1.hour)
      request(%w[config], at: now + 2.hours)
      expect(described_class.availability(host:, now: now + 2.hours)["config"].latest.requested_at).to eq(now + 2.hours)
    end
  end
end
