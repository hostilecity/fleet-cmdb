require "rails_helper"

# #251, ADR 0018: a host whose agent systemd keeps restarting after the update counts as failed for its stage, so a
# release that leaks slowly halts with the first hosts that run it, although each process confirms and heartbeats.
RSpec.describe "Rollouts and restart loops (#251)" do
  let(:release) { release_for_rollout("0.3.0") }
  let!(:canary) { host_running("0.2.0").first }
  let!(:other) { host_running("0.2.0").first }
  let(:rollout) { start_rollout(release:, canaries: [ canary ]) }
  let(:member) { rollout.rollout_hosts.find_by!(host: canary) }

  def credential_id(host) = host.agent_credentials.active.pick(:id)

  def confirm(host)
    Host.transaction do
      Rollouts.record_result!(host_id: host.id, credential_id: credential_id(host), payload: update_result(rollout).deep_stringify_keys)
    end
  end

  def offer(host) = Host.transaction { Rollouts.directive_for(host_id: host.id, agent_version: "0.2.0") }

  # A heartbeat from host showing systemd restarted the agent `restarts` times since the last one.
  def restarted(host, restarts)
    host.reload
    known = host.agent_restarts || 0
    agent_time = Time.current
    Host.transaction do
      unless host.agent_restarts
        Liveness.record_heartbeat!(host_id: host.id, credential_id: credential_id(host), agent_version: "0.3.0", agent_schema_version: 1,
                                   agent_time:, process: { "started_at" => (agent_time - 1).iso8601(3), "restarts" => 0, "last_stop" => nil })
      end
      Liveness.record_heartbeat!(host_id: host.id, credential_id: credential_id(host), agent_version: "0.3.0", agent_schema_version: 1,
                                 agent_time:, process: { "started_at" => agent_time.iso8601(3), "restarts" => known + restarts,
                                                         "last_stop" => { "result" => "oom-kill", "exit_code" => "killed", "exit_status" => 9,
                                                                          "stopped_at" => (agent_time - 10).iso8601(3) } })
    end
  end

  before do
    rollout
    travel 1.second
    offer(canary)
  end

  it "marks a confirmed canary that restarts more than 3 times in 24 hours, halts the rollout, and audits both" do
    confirm(canary)
    # The canary confirmed, so the next stage opened; its hosts are offered later, unless the rollout halts first.
    expect(rollout.reload.current_stage).to be >= 1
    expect(rollout.rollout_hosts.find_by!(host: other).state).to eq("pending")
    3.times do
      travel 5.minutes
      restarted(canary, 1)
    end
    expect(member.reload.state).to eq("confirmed")
    expect(rollout.reload.state).to eq("running")
    travel 5.minutes
    restarted(canary, 1)
    expect(member.reload).to have_attributes(state: "restart_loop", resolved_at: be_within(1.second).of(Time.current))
    expect(rollout.reload).to have_attributes(state: "halted", halted_by: nil)
    expect(rollout.halt_reason).to eq("#{canary.name} restarted 4 times within 24 hours of the update.")
    expect(audit_actions.last(2)).to eq([ Audit::Actions::UPDATE_RESTART_LOOP, Audit::Actions::ROLLOUT_HALTED ])
    entry = AuditEntry.find_by!(action: Audit::Actions::UPDATE_RESTART_LOOP)
    expect(entry.changeset).to include("host_id" => canary.id, "rollout_id" => rollout.id, "version" => "0.3.0", "restarts" => 4, "window_hours" => 24)
    # Halted: the next stage's hosts are not offered the update, and the canary is not marked twice.
    expect(offer(other)).to be_nil
    expect { restarted(canary, 1) }.not_to(change { AuditEntry.count })
  end

  it "counts a host that is still updating, and keeps the mark when its success arrives late" do
    restarted(canary, 4)
    expect(member.reload.state).to eq("restart_loop")
    confirm(canary)
    expect(member.reload.state).to eq("restart_loop")
    expect(AgentUpdate.where(host: canary).sole.outcome).to eq("succeeded")
    Rollouts.resume!(rollout.reload, actor: create(:operator))
    expect(rollout.reload).to have_attributes(state: "running", current_stage: 0) # the stage cannot complete
  end

  it "counts only restarts since the host was offered the update, and within the window" do
    member.update_columns(offered_at: Time.current)
    canary.update_columns(agent_restarts: 0, agent_recent_restarts: [ 1.minute.ago ] * 3)
    restarted(canary, 1)
    expect(member.reload.state).to eq("updating") # the three before the offer do not count
    member.update_columns(offered_at: 2.days.ago)
    canary.update_columns(agent_recent_restarts: [ 25.hours.ago ] * 3)
    restarted(canary, 1)
    expect(member.reload.state).to eq("updating") # older than the window
  end

  it "follows the settings" do
    Rails.configuration.x.restart_loop.limit = 1
    Rails.configuration.x.restart_loop.window = 1.hour
    restarted(canary, 1)
    expect(member.reload.state).to eq("updating")
    restarted(canary, 1)
    expect(member.reload.state).to eq("restart_loop")
    expect(rollout.reload.halt_reason).to end_with("restarted 2 times within 1 hours of the update.")
  end

  it "marks a host of a halted rollout without halting it again, and leaves a failed host and one outside rollouts alone" do
    Rollouts.halt!(rollout, actor: create(:operator))
    restarted(canary, 4)
    expect(member.reload.state).to eq("restart_loop")
    expect(audit_actions.count(Audit::Actions::ROLLOUT_HALTED)).to eq(1)

    member.update_columns(state: "failed")
    expect(Host.transaction { Rollouts.restarts_seen!(host: canary.reload, recent: [ Time.current ] * 9) }).to be_nil
    expect(member.reload.state).to eq("failed")
    loner = host_running("0.2.0").first
    expect(Host.transaction { Rollouts.restarts_seen!(host: loner, recent: [ Time.current ] * 9) }).to be_nil
  end

  it "re-reads the rollout and the host under their locks, and does nothing when they moved on meanwhile" do
    allow(Rollout).to receive(:lock).and_wrap_original do |original, *args|
      RolloutHost.where(id: member.id).update_all(state: "rolled_back")
      original.call(*args)
    end
    expect(Host.transaction { Rollouts.restarts_seen!(host: canary.reload, recent: [ Time.current ] * 9) }).to be_nil
    expect(member.reload.state).to eq("rolled_back")
    expect(rollout.reload.state).to eq("running")
  end

  describe "the settings at boot" do
    def boot(setting, key, value)
      saved = ENV.fetch(setting, nil)
      ENV[setting] = value
      Rails.configuration.x.restart_loop.delete(key)
      load Rails.root.join("config/initializers/rollouts.rb")
      Rails.configuration.x.restart_loop.public_send(key)
    ensure
      ENV[setting] = saved
    end

    it "defaults to more than 3 restarts in 24 hours, as the owner decided, and takes whole numbers in range" do
      expect(boot("FLEET_RESTART_LOOP_RESTARTS", :limit, nil)).to eq(3)
      expect(boot("FLEET_RESTART_LOOP_RESTARTS", :limit, "31")).to eq(31)
      expect(boot("FLEET_RESTART_LOOP_WINDOW_HOURS", :window, nil)).to eq(24.hours)
      expect(boot("FLEET_RESTART_LOOP_WINDOW_HOURS", :window, "168")).to eq(168.hours)
    end

    it "stops the server at boot, naming the setting, for anything else" do
      [ "", "0", "32", "2.5", "three" ].each do |value|
        expect { boot("FLEET_RESTART_LOOP_RESTARTS", :limit, value) }
          .to raise_error(RuntimeError, "FLEET_RESTART_LOOP_RESTARTS must be a whole number of restarts from 1 to 31 (got #{value.inspect})")
      end
      [ "", "0", "169", "1.5", "day" ].each do |value|
        expect { boot("FLEET_RESTART_LOOP_WINDOW_HOURS", :window, value) }
          .to raise_error(RuntimeError, "FLEET_RESTART_LOOP_WINDOW_HOURS must be a whole number of hours from 1 to 168 (got #{value.inspect})")
      end
    end
  end
end
