require "rails_helper"

# P1-S09, FR-1.4, AC-1.2: liveness from last_seen_at with configurable thresholds and recorded transitions.
RSpec.describe Liveness do
  let(:start) { Time.zone.parse("2026-03-01 12:00:00 UTC") }
  let!(:host) { enrolled_host.first }

  def heartbeat_at(time)
    travel_to(time) { record_heartbeat(host, agent_time: time) }
  end

  def evaluate_at(time) = travel_to(time) { LivenessEvaluationJob.perform_now }

  def heartbeat_at_for(target, time) = travel_to(time) { record_heartbeat(target, agent_time: time) }

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

  it "never finds revoked or retired hosts again, and evaluates a host again once it is active (review of #220)" do
    revoked, retired, other = Array.new(3) { enrolled_host.first }
    [ host, revoked, retired, other ].each { |h| heartbeat_at_for(h, start) }
    revoked.revoke!(actor: Audit::SYSTEM)
    retired.retire!(actor: Audit::SYSTEM)
    expect(HostLiveness.where(host_id: [ revoked, retired ]).pluck(:evaluated)).to eq([ false, false ])
    expect(travel_to(start + 20.minutes) { described_class.evaluate! }).to eq(2) # host and other

    statements = []
    callback = ->(*, payload) { statements << payload }
    quiet = ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { travel_to(start + 20.minutes) { described_class.evaluate! } }
    expect(quiet).to eq(0)
    expect(statements.count { |payload| payload[:name] == "Liveness candidates" }).to eq(1)
    expect(statements.map { |payload| payload[:sql] }.grep(/\bFROM "?hosts"?\b/)).to be_empty # no lookup of the hosts left behind
    expect(HostLiveness.where(host_id: [ revoked, retired ]).pluck(:liveness_status)).to eq(%w[online online]) # not evaluated

    revoked.begin_reenrollment!(actor: Audit::SYSTEM)
    revoked.activate!(actor: Audit::SYSTEM)
    expect(revoked.reload.liveness.evaluated).to be(true)
    expect(travel_to(start + 20.minutes) { described_class.evaluate! }).to eq(1)
    expect(revoked.reload.liveness_status).to eq("offline")
  end

  it "reads the clock and thresholds only after taking the evaluation lock" do
    record_heartbeat(host, agent_time: Time.current)
    set_liveness(host, last_seen_at: 20.minutes.ago)
    locked_at = nil
    callback = ->(*, payload) { locked_at ||= Time.current if payload[:sql].include?("pg_try_advisory_lock") }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { described_class.evaluate! }
    expect(locked_at).to be_present
    expect(host.status_events.chronological.last).to have_attributes(to_status: "offline", occurred_at: be >= locked_at.floor(6))
  end

  it "evaluates many hosts in one run" do
    others = Array.new(3) { enrolled_host.first }
    ([ host ] + others).each { |h| travel_to(start) { record_heartbeat(h, agent_time: start) } }
    expect(travel_to(start + 20.minutes) { described_class.evaluate! }).to eq(4)
    expect(HostLiveness.where(host_id: [ host, *others ]).pluck(:liveness_status).uniq).to eq([ "offline" ])
  end

  it "moves hosts in transactions of at most BATCH_SIZE hosts, each with its own events (scale assessment)" do
    stub_const("Liveness::BATCH_SIZE", 2)
    others = Array.new(4) { enrolled_host.first }
    ([ host ] + others).each { |h| travel_to(start) { record_heartbeat(h, agent_time: start) } }
    statements = []
    callback = ->(*, payload) { statements << payload }
    written = ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { travel_to(start + 20.minutes) { described_class.evaluate! } }

    expect(written).to eq(5)
    expect(HostLiveness.where(host_id: [ host, *others ]).pluck(:liveness_status).uniq).to eq([ "offline" ])
    expect(HostStatusEvent.where(reason: "evaluation", to_status: "offline").count).to eq(5)
    # One pass over host_liveness, 2 + 2 + 1, the short batch ending the run; each batch locks only the hosts it found.
    expect(statements.count { |payload| payload[:name] == "Liveness candidates" }).to eq(3)
    expect(statements.count { |payload| payload[:sql].include?("FOR NO KEY UPDATE SKIP LOCKED") }).to eq(3)
    expect(statements.count { |payload| payload[:name] == "Liveness transitions" }).to eq(3)
    expect(statements.select { |payload| payload[:sql].match?(/\bFROM "?hosts"?\b/) }.map { |payload| payload[:sql] }).to all(include("SKIP LOCKED"))
  end

  it "refreshes the fleet pages for the batches that committed when a later batch fails, then releases the lock (review of #186)" do
    stub_const("Liveness::BATCH_SIZE", 1)
    others = Array.new(2) { enrolled_host.first }
    ([ host ] + others).each { |h| travel_to(start) { record_heartbeat(h, agent_time: start) } }
    calls = 0
    allow(HostStatusEvent).to receive(:insert_all!).and_wrap_original do |original, *args|
      raise ActiveRecord::StatementInvalid, "simulated failure" if (calls += 1) == 2

      original.call(*args)
    end
    allow(FleetBroadcast).to receive(:hosts_changed)

    expect { travel_to(start + 20.minutes) { described_class.evaluate! } }.to raise_error(ActiveRecord::StatementInvalid)
    first = HostLiveness.where(liveness_status: "offline").pluck(:host_id)
    expect(first.size).to eq(1) # the first batch committed; the second rolled back
    expect(FleetBroadcast).to have_received(:hosts_changed).with(first)
    expect(travel_to(start + 20.minutes) { described_class.evaluate! }).to eq(2) # the lock was released; the next run does the rest
  end

  it "releases the evaluation lock after a run, so the next run is not refused" do
    heartbeat_at(start)
    expect(travel_to(start + 20.minutes) { described_class.evaluate! }).to eq(1)
    held = "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = #{Liveness::EVALUATION_LOCK_KEY} AND pid = pg_backend_pid()"
    expect(Host.connection.select_value(held)).to eq(0) # this connection's lock only: other databases share the cluster (review of #186)
  end

  it "closes the connection when the lock cannot be released, so the lock goes with it and no later run is blocked" do
    heartbeat_at(start)
    connection = Host.connection
    allow(connection).to receive(:select_value).and_call_original
    allow(connection).to receive(:select_value).with(/pg_advisory_unlock/).and_raise(ActiveRecord::ConnectionFailed)
    allow(connection).to receive(:throw_away!)

    expect(travel_to(start + 20.minutes) { described_class.evaluate! }).to eq(1)
    expect(connection).to have_received(:throw_away!)
  ensure
    connection&.execute("SELECT pg_advisory_unlock_all()") # throw_away! was stubbed, so the test's connection still holds it
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

  it "reads both thresholds in one query, so an evaluation never mixes old and new values" do
    described_class.update_liveness_thresholds!(online_minutes: 10, stale_minutes: 30, actor: Audit::SYSTEM)
    queries = []
    callback = ->(*, payload) { queries << payload[:sql] unless payload[:name] == "SCHEMA" }
    thresholds = ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { described_class.liveness_thresholds }
    expect(queries.size).to eq(1)
    expect(thresholds).to eq(online: 10.minutes, stale: 30.minutes)
  end

  it "only stores defined keys" do
    expect(described_class.new(key: "anything", value: 1)).not_to be_valid
  end
end
