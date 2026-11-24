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
    travel 1.second # restarts at the offer's own instant happened before it (N2)
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
    expect(rollout.halt_reason).to eq("#{canary.name} restarted 4 times within 24 hours of the update; " \
                                      "last stop: killed at its memory limit (systemd: oom-kill, killed by signal 9 (SIGKILL)).")
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
    expect(rollout.reload.halt_reason).to include("restarted 2 times within 1 hour of the update;")
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

  describe "the stage observation time (owner decision 2026-11-23, review of #307, S4)" do
    before { Rails.configuration.x.rollouts.stage_observe = 30.minutes }

    def minute_job = RolloutTimeoutJob.perform_now

    it "keeps a confirmed canary stage open, so a leak that needs 24 minutes for 4 restarts halts at the canaries" do
      confirm(canary)
      expect(rollout.reload).to have_attributes(current_stage: 0, stage_confirmed_at: be_within(1.second).of(Time.current))
      expect(Rollouts.observing_until(rollout)).to be_within(1.second).of(30.minutes.from_now)
      # A restart every 6 minutes: under the start limit, never recovery mode. The minute job keeps the stage open.
      4.times do |n|
        6.times do
          travel 1.minute
          minute_job
        end
        expect(rollout.reload.current_stage).to eq(0)
        restarted(canary, 1)
        expect(rollout.reload.state).to eq(n < 3 ? "running" : "halted")
      end
      expect(member.reload.state).to eq("restart_loop")
      expect(rollout.rollout_hosts.where.not(host: canary)).to be_empty # no other host was chosen, let alone offered
    end

    it "opens the next stage once the observation time has passed without a restart loop, and observes the last one too" do
      confirm(canary)
      travel 29.minutes
      minute_job
      expect(rollout.reload.current_stage).to eq(0)
      travel 1.minute
      minute_job
      # The empty 25% stage is not observed; the 100% stage takes the other host.
      expect(rollout.reload).to have_attributes(current_stage: 2, stage_confirmed_at: nil, state: "running")
      offer(other)
      travel 1.second
      confirm(other)
      expect(rollout.reload).to have_attributes(state: "running", stage_confirmed_at: be_present)
      travel 31.minutes
      minute_job
      expect(rollout.reload.state).to eq("completed")
      expect(audit_actions.last).to eq(Audit::Actions::ROLLOUT_COMPLETED)
    end

    it "observes the last stage too: still running 29 minutes after it confirmed, completed after 30 (re-check, S2)" do
      confirm(canary)
      travel 30.minutes
      minute_job
      expect(rollout.reload.current_stage).to eq(2)
      offer(other)
      travel 1.second
      confirm(other)
      travel 29.minutes
      minute_job
      expect(rollout.reload.state).to eq("running")
      travel 1.minute
      minute_job
      expect(rollout.reload.state).to eq("completed")
    end

    it "observes a host that confirms after an early Advance, also into an empty last stage (re-check, S4)" do
      other.update_columns(agent_version: "0.3.0") # the last stage then has no host
      Rollouts.advance!(rollout.reload, actor: create(:operator))
      Rollouts.advance!(rollout.reload, actor: create(:operator)) if rollout.reload.current_stage < rollout.stage_percents.size
      expect(rollout.reload).to have_attributes(state: "running", current_stage: rollout.stage_percents.size)
      confirm(canary) # the canary, still updating when the operator advanced, confirms now
      expect(rollout.reload).to have_attributes(state: "running", last_confirmed_at: be_within(1.second).of(Time.current))
      travel 29.minutes
      minute_job
      expect(rollout.reload.state).to eq("running")
      travel 1.minute
      minute_job
      expect(rollout.reload.state).to eq("completed")
    end

    it "lets an operator advance at once, and observes again from a resume" do
      confirm(canary)
      Rollouts.halt!(rollout.reload, actor: create(:operator))
      travel 40.minutes
      Rollouts.resume!(rollout.reload, actor: create(:operator))
      expect(rollout.reload).to have_attributes(current_stage: 0, stage_confirmed_at: be_within(1.second).of(Time.current))
      minute_job
      expect(rollout.reload.current_stage).to eq(0)
      Rollouts.advance!(rollout.reload, actor: create(:operator))
      expect(rollout.reload.current_stage).to be >= 1
    end

    it "does nothing for a job delivered while the stage is still observed" do
      confirm(canary)
      expect { Rollouts.advance_confirmed!(rollout.id, from: 0) }.not_to(change { rollout.reload.current_stage })
    end
  end

  describe "a host already looping before its offer (owner decision 2026-11-23, review of #307, S6)" do
    it "does not count, and says it was looping before" do
      member.update_columns(restarts_before_offer: 4, restart_limit: 3, restart_window_hours: 24, restart_loop_before: false)
      restarted(canary, 9)
      expect(member.reload.state).to eq("updating")
      expect(rollout.reload.state).to eq("running")
      expect(helper_words(member)).to start_with("looping before this update (4 restarts in the 24 hours before it), so not counted until ")
      member.update_columns(restarts_before_offer: 3) # exactly the limit stored at the offer: not looping, so counted
      restarted(canary, 4)
      expect(member.reload.state).to eq("restart_loop")
    end

    it "stores the restarts within the window before the first offer, in the offer's own statement" do
      loner = host_running("0.2.0").first
      loner.update_columns(agent_recent_restarts: [ 1.minute.ago, 2.hours.ago, 23.hours.ago, 25.hours.ago ])
      Rollouts.cancel!(rollout, actor: create(:operator))
      second = start_rollout(release: release_for_rollout("0.4.0"), canaries: [ loner ])
      offer(loner)
      expect(second.rollout_hosts.sole.restarts_before_offer).to eq(3)
      expect(member.reload.restarts_before_offer).to eq(0)
    end

    it "ends the exemption one window after the offer: from then on its restarts count (owner decision 2026-11-24)" do
      member.update_columns(restarts_before_offer: 9, restart_limit: 3, restart_window_hours: 24, restart_loop_before: false)
      restarted(canary, 9)
      expect(member.reload.state).to eq("updating")
      travel 24.hours
      expect(helper_words(member)).to start_with("looping before this update (9 restarts in the 24 hours before it); counted since ")
      4.times do
        travel 5.minutes
        restarted(canary, 1)
      end
      expect(member.reload.state).to eq("restart_loop")
    end

    it "keeps the limit and window of the offer when the settings change during the rollout (N2)" do
      member.update_columns(restarts_before_offer: 4, restart_limit: 3, restart_window_hours: 24, restart_loop_before: false)
      Rails.configuration.x.restart_loop.limit = 10
      Rails.configuration.x.restart_loop.window = 2.hours
      expect(Rollouts.exempt_from_restarts?(member.reload)).to be(true)
      expect(helper_words(member)).to start_with("looping before this update (4 restarts in the 24 hours before it)")
      expect(Rollouts.exemption_ends_at(member)).to eq(member.offered_at + 24.hours)
    end

    it "halts a fix release that leaks the same way at its canary, although it looped before its offer (the re-check's probe)" do
      # Rollout A (0.3.0) leaks: its canary is marked and A halts. The operator cancels A.
      restarted(canary, 4)
      expect(member.reload.state).to eq("restart_loop")
      Rollouts.cancel!(rollout.reload, actor: create(:operator))
      # An hour later, rollout B (0.4.0) with the same canary. Its first offer sees 4 restarts before it, but A marked
      # the host: not exempt. B leaks the same way, and halts at the canary.
      travel 1.hour
      b = start_rollout(release: release_for_rollout("0.4.0"), canaries: [ canary ])
      offer(canary)
      b_member = b.rollout_hosts.find_by!(host: canary)
      expect(b_member).to have_attributes(restarts_before_offer: 4, restart_limit: 3, restart_window_hours: 24, restart_loop_before: true)
      expect(helper_words(b_member)).to eq("looping before this update (4 restarts in the 24 hours before it), after an earlier rollout's update, so counted")
      travel 1.second
      4.times do
        travel 5.minutes
        restarted(canary, 1)
      end
      expect(b_member.reload.state).to eq("restart_loop")
      expect(b.reload).to have_attributes(state: "halted", current_stage: 0)
    end

    it "is not ended by an earlier rollout's mark older than the window" do
      restarted(canary, 4)
      Rollouts.cancel!(rollout.reload, actor: create(:operator))
      travel 25.hours
      canary.update_columns(agent_recent_restarts: [ 1.hour.ago ] * 4)
      b = start_rollout(release: release_for_rollout("0.4.0"), canaries: [ canary ])
      offer(canary)
      expect(b.rollout_hosts.find_by!(host: canary)).to have_attributes(restarts_before_offer: 4, restart_loop_before: false)
    end

    it "counts the window's edges at the offer: a restart exactly a window before is out, one at the offer's instant is in (N3)" do
      loner = host_running("0.2.0").first
      Rollouts.cancel!(rollout, actor: create(:operator))
      second = start_rollout(release: release_for_rollout("0.4.0"), canaries: [ loner ])
      freeze_time do
        loner.update_columns(agent_recent_restarts: [ Time.current, 1.hour.ago, 24.hours.ago ])
        offer(loner)
      end
      expect(second.rollout_hosts.sole.restarts_before_offer).to eq(2)
    end

    def helper_words(member) = Object.new.extend(ActionView::Helpers::TextHelper, RolloutsHelper).looping_before_words(member)
  end

  it "does not count a restart at the offer's own instant (review of #307, N2; re-check, N3)" do
    travel_back
    freeze_time do
      at_offer = member.reload.offered_at
      canary.update_columns(agent_recent_restarts: [ at_offer ] * 4 + [ at_offer + 1 ] * 3, agent_restarts: 7)
      expect(Host.transaction { Rollouts.restarts_seen!(host: canary.reload, recent: canary.agent_recent_restarts, now: at_offer + 2) }).to be_nil
      expect(Host.transaction { Rollouts.restarts_seen!(host: canary, recent: [ at_offer + 1 ] * 4, now: at_offer + 2) }).to be_present
    end
  end

  it "keeps the restart_loop mark's time when a success arrives late (review of #307, N3)" do
    restarted(canary, 4)
    marked = member.reload.resolved_at
    travel 5.minutes
    confirm(canary)
    expect(member.reload).to have_attributes(state: "restart_loop", resolved_at: marked)
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

    it "observes a confirmed stage for 30 minutes by default, from 0 (none) to a week" do
      saved = ENV.fetch("FLEET_ROLLOUT_STAGE_OBSERVE_MINUTES", nil)
      boot_observe = lambda do |value|
        ENV["FLEET_ROLLOUT_STAGE_OBSERVE_MINUTES"] = value
        Rails.configuration.x.rollouts.delete(:stage_observe)
        load Rails.root.join("config/initializers/rollouts.rb")
        Rails.configuration.x.rollouts.stage_observe
      end
      expect(boot_observe.(nil)).to eq(30.minutes)
      expect(boot_observe.("0")).to eq(0.minutes)
      expect(boot_observe.("10080")).to eq(10_080.minutes)
      [ "", "-1", "10081", "1.5", "half" ].each do |value|
        expect { boot_observe.(value) }
          .to raise_error(RuntimeError, "FLEET_ROLLOUT_STAGE_OBSERVE_MINUTES must be a whole number of minutes from 0 to 10080 (got #{value.inspect})")
      end
    ensure
      ENV["FLEET_ROLLOUT_STAGE_OBSERVE_MINUTES"] = saved
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
