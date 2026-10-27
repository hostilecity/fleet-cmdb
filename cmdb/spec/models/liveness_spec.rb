require "rails_helper"

# P1-S09, FR-1.4, AC-1.2: liveness from last_seen_at with configurable thresholds and recorded transitions.
RSpec.describe Liveness do
  let(:start) { Time.zone.parse("2026-03-01 12:00:00 UTC") }
  let!(:host) { enrolled_host.first }

  def heartbeat_at(time)
    travel_to(time) { Host.transaction { described_class.record_heartbeat!(host, agent_version: "0.1.0", agent_schema_version: 1, agent_time: time) } }
  end

  def evaluate_at(time) = travel_to(time) { LivenessEvaluationJob.perform_now }

  it "moves a host online, stale, then offline at the default thresholds, and back online on a heartbeat (AC-1.2)" do
    heartbeat_at(start)
    { 2.minutes => "online", 3.minutes => "stale", 14.minutes => "stale", 15.minutes => "offline", 60.minutes => "offline" }.each do |elapsed, expected|
      evaluate_at(start + elapsed)
      expect(host.reload.liveness_status).to eq(expected), "after #{elapsed.inspect}"
    end
    heartbeat_at(start + 61.minutes)
    expect(host.reload.liveness_status).to eq("online")

    events = host.status_events.chronological.pluck(:from_status, :to_status, :reason, :occurred_at)
    expect(events).to eq([
      [ nil, "online", "heartbeat", start ],
      [ "online", "stale", "evaluation", start + 3.minutes ],
      [ "stale", "offline", "evaluation", start + 15.minutes ],
      [ "offline", "online", "heartbeat", start + 61.minutes ]
    ])
  end

  it "applies changed thresholds on the next run" do
    heartbeat_at(start)
    evaluate_at(start + 5.minutes)
    expect(host.reload.liveness_status).to eq("stale")
    Setting.update_liveness_thresholds!(online_minutes: 10, stale_minutes: 30, actor: Audit::SYSTEM)
    evaluate_at(start + 5.minutes)
    expect(host.reload.liveness_status).to eq("online")
    evaluate_at(start + 20.minutes)
    expect(host.reload.liveness_status).to eq("stale")
  end

  it "writes no events when re-run without changes" do
    heartbeat_at(start)
    evaluate_at(start + 4.minutes)
    expect { 3.times { evaluate_at(start + 4.minutes) } }.not_to change(HostStatusEvent, :count)
    expect(described_class.evaluate!(now: start + 4.minutes)).to eq(0)
  end

  it "leaves hosts that never sent a heartbeat out of online ('awaiting first contact')" do
    evaluate_at(start + 1.hour)
    expect(host.reload.liveness_status).to be_nil
    expect(host.display_status).to eq("awaiting first contact")
    expect(host.status_events).to be_empty
  end

  it "does not evaluate hosts that are not active, which show their enrollment state" do
    heartbeat_at(start)
    host.revoke!(actor: Audit::SYSTEM)
    expect { evaluate_at(start + 1.hour) }.not_to change(HostStatusEvent, :count)
    expect(host.reload.display_status).to eq("revoked")
  end

  it "evaluates many hosts in one run" do
    others = Array.new(3) { enrolled_host.first }
    ([ host ] + others).each { |h| travel_to(start) { Host.transaction { described_class.record_heartbeat!(h, agent_version: "0.1.0", agent_schema_version: 1, agent_time: start) } } }
    expect(travel_to(start + 20.minutes) { described_class.evaluate! }).to eq(4)
    expect(Host.active.pluck(:liveness_status).uniq).to eq([ "offline" ])
  end
end

RSpec.describe Setting do
  it "defaults the liveness thresholds to 3 and 15 minutes" do
    expect(described_class.liveness_thresholds).to eq(online: 3.minutes, stale: 15.minutes)
  end

  it "validates and audits threshold changes" do
    described_class.update_liveness_thresholds!(online_minutes: "5", stale_minutes: "20", actor: Audit::SYSTEM)
    expect(described_class.liveness_thresholds).to eq(online: 5.minutes, stale: 20.minutes)
    changes = AuditEntry.where(action: Audit::Actions::SETTING_CHANGED).chronological.pluck(:changeset)
    expect(changes).to eq([ { "liveness.online_threshold_minutes" => [ 3, 5 ] }, { "liveness.stale_threshold_minutes" => [ 15, 20 ] } ])

    expect { described_class.update_liveness_thresholds!(online_minutes: 5, stale_minutes: 20, actor: Audit::SYSTEM) }
      .not_to change(AuditEntry, :count)
  end

  it "rejects invalid thresholds without changing anything" do
    [ [ 15, 15 ], [ 20, 10 ], [ "x", 10 ], [ 0, 10 ], [ 3, 20_000 ], [ 2.5, 10 ] ].each do |online, stale|
      expect { described_class.update_liveness_thresholds!(online_minutes: online, stale_minutes: stale, actor: Audit::SYSTEM) }
        .to raise_error(Setting::Invalid)
    end
    expect(described_class.count).to eq(0)
    expect(described_class.liveness_thresholds).to eq(online: 3.minutes, stale: 15.minutes)
  end

  it "only stores defined keys" do
    expect(described_class.new(key: "anything", value: 1)).not_to be_valid
  end
end
