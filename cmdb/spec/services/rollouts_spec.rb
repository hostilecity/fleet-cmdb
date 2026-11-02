require "rails_helper"

# P1-UPDATES (P1-S17): staged rollouts, the heartbeat directive, outcomes, and the halt rules (AC-1.9, AC-1.10).
RSpec.describe Rollouts do
  let(:operator) { create(:operator) }
  let(:release) { release_for_rollout("0.3.0") }

  def credential_id(host) = host.agent_credentials.active.pick(:id)

  def report(rollout, host, **overrides)
    Host.transaction do
      Rollouts.record_result!(host_id: host.id, credential_id: credential_id(host), payload: update_result(rollout, **overrides).deep_stringify_keys)
    end
  end

  def directive(host, version = "0.2.0") = Host.transaction { Rollouts.directive_for(host_id: host.id, agent_version: version) }

  describe ".start!" do
    it "opens stage 0 with the canaries that run an older version and audits it" do
      canary, = host_running("0.2.0")
      current, = host_running("0.3.0")
      other, = host_running("0.2.0")
      rollout = Rollouts.start!(release:, actor: operator, canary_host_ids: [ canary.id, current.id, 0 ])
      expect(rollout).to have_attributes(state: "running", current_stage: 0, stage_percents: [ 25, 100 ], started_by: operator, agent_release: release)
      expect(rollout.rollout_hosts.pluck(:host_id, :stage, :state)).to eq([ [ canary.id, 0, "pending" ] ])
      entry = AuditEntry.find_by!(action: Audit::Actions::ROLLOUT_STARTED)
      expect(entry).to have_attributes(actor_type: "operator", actor_id: operator.id, target_type: "Rollout", target_id: rollout.id)
      expect(entry.changeset).to include("version" => [ nil, "0.3.0" ], "hosts_added" => 1, "stage_percents" => [ 25, 100 ])
      expect(other.rollout_hosts).to be_empty
    end

    it "takes canaries by tag as well" do
      tagged, = host_running("0.2.0", tags: [ "Canary" ])
      host_running("0.2.0")
      rollout = Rollouts.start!(release:, actor: operator, canary_tag: " Canary ")
      expect(rollout.canary_tag).to eq("canary")
      expect(rollout.rollout_hosts.pluck(:host_id)).to eq([ tagged.id ])
    end

    it "skips hosts that are not active or have not reported a version" do
      silent, = enrolled_host
      silent.update_columns(agent_version: nil)
      pending_host = create(:host)
      retired = create(:host, :retired)
      expect { Rollouts.start!(release:, actor: operator, canary_host_ids: [ silent.id, pending_host.id, retired.id ]) }
        .to raise_error(Rollouts::Invalid, /None of the canaries/)
      expect(Rollout.count).to eq(0)
      expect(AuditEntry.where(action: Audit::Actions::ROLLOUT_STARTED)).to be_empty
    end

    it "needs canaries" do
      expect { Rollouts.start!(release:, actor: operator) }.to raise_error(Rollouts::Invalid, /canary/)
    end

    [ [], [ 50 ], [ 100, 25 ], [ 25, 25, 100 ], [ 0, 100 ], [ 25, 101 ], [ "x", 100 ], nil ].each do |stages|
      it "refuses the stages #{stages.inspect}" do
        host, = host_running("0.2.0")
        expect { Rollouts.start!(release:, actor: operator, canary_host_ids: [ host.id ], stage_percents: stages) }
          .to raise_error(Rollouts::Invalid, /Stages/)
      end
    end

    it "runs one rollout at a time, whether running or halted" do
      host, = host_running("0.2.0")
      rollout = start_rollout(release:, canaries: [ host ])
      expect { start_rollout(release:, canaries: [ host ]) }.to raise_error(Rollouts::Invalid, /already open/)
      Rollouts.halt!(rollout, actor: operator)
      expect { start_rollout(release:, canaries: [ host ]) }.to raise_error(Rollouts::Invalid, /already open/)
      Rollouts.cancel!(rollout, actor: operator)
      expect { start_rollout(release:, canaries: [ host ]) }.not_to raise_error
    end

    it "is held to one open rollout by the database too" do
      host, = host_running("0.2.0")
      start_rollout(release:, canaries: [ host ])
      allow(Rollout).to receive(:open_now).and_return(Rollout.none)
      expect { start_rollout(release:, canaries: [ host ]) }.to raise_error(Rollouts::Invalid, /already open/)
    end

    it "never lets a targeted release be deleted" do
      host, = host_running("0.2.0")
      start_rollout(release:, canaries: [ host ])
      expect { release.destroy! }.to raise_error(ActiveRecord::DeleteRestrictionError)
      expect { release.delete }.to raise_error(ActiveRecord::StatementInvalid, /rollouts/) # the foreign key; the error class varies with PostgreSQL's version
    end
  end

  describe "stages" do
    let!(:canary) { host_running("0.2.0").first }
    let!(:others) { Array.new(7) { host_running("0.2.0").first } }
    let!(:rollout) { start_rollout(release:, canaries: [ canary ]) }

    def confirm_all(rollout)
      rollout.rollout_hosts.where(stage: rollout.reload.current_stage).includes(:host).find_each do |member|
        report(rollout, member.host)
      end
    end

    it "advances by itself when every host of a stage has confirmed, up to the percentage, and then completes" do
      expect(rollout.rollout_hosts.count).to eq(1)
      confirm_all(rollout)
      expect(rollout.reload).to have_attributes(state: "running", current_stage: 1)
      expect(rollout.rollout_hosts.where(stage: 1).count).to eq(1) # 25% of 8 hosts is 2; the canary is one of them
      confirm_all(rollout)
      expect(rollout.reload).to have_attributes(state: "running", current_stage: 2)
      expect(rollout.rollout_hosts.count).to eq(8)
      confirm_all(rollout)
      expect(rollout.reload).to have_attributes(state: "completed", open_slot: nil, finished_at: be_present)
      expect(audit_actions.grep(/rollout\./)).to eq(%w[rollout.started rollout.advanced rollout.advanced rollout.completed])
      advanced = AuditEntry.where(action: Audit::Actions::ROLLOUT_ADVANCED).chronological.first
      expect(advanced).to have_attributes(actor_type: "system")
      expect(advanced.changeset).to include("stage" => [ 0, 1 ], "hosts_added" => 1)
      expect(Rollout.current).to be_nil
    end

    it "does not advance while a host has not confirmed" do
      rollout.rollout_hosts.first.update!(state: "updating")
      Rollouts.send(:advance_if_confirmed!, rollout, actor: Audit::SYSTEM)
      expect(rollout.reload.current_stage).to eq(0)
    end

    it "lets an operator advance without waiting, but not past the final stage" do
      Rollouts.advance!(rollout, actor: operator)
      expect(rollout.reload.current_stage).to eq(1)
      entry = AuditEntry.where(action: Audit::Actions::ROLLOUT_ADVANCED).sole
      expect(entry).to have_attributes(actor_type: "operator", actor_id: operator.id)
      expect(entry.changeset["reason"]).to eq("advanced by an operator")
      Rollouts.advance!(rollout, actor: operator)
      expect(rollout.reload).to have_attributes(current_stage: 2, state: "running")
      expect { Rollouts.advance!(rollout, actor: operator) }.to raise_error(Rollouts::Invalid, /final stage/)
    end

    it "advances through a stage that adds no host" do
      host_total = Host.count
      expect(host_total).to be >= 8
      two_stage = Rollout.find(rollout.id)
      two_stage.update_columns(stage_percents: [ 10, 20, 100 ]) # 10% of 8 hosts is 1: already the canary
      Rollouts.advance!(two_stage, actor: operator)
      expect(two_stage.reload.current_stage).to eq(2) # the empty stage 1 counted as confirmed
      expect(two_stage.rollout_hosts.where(stage: 2).count).to eq(1) # 20% of 8 hosts is 2
    end

    it "does not offer a later stage's hosts before it opens, and offers them after" do
      expect(directive(canary)).to be_present
      expect(Host.where.not(id: canary.id).map { |host| directive(host) }.compact).to be_empty
      Rollouts.advance!(rollout, actor: operator)
      chosen = rollout.rollout_hosts.where(stage: 1).sole.host
      expect(directive(chosen)).to be_present
    end
  end

  describe ".directive_for" do
    let!(:host) { host_running("0.2.0").first }
    let!(:rollout) { start_rollout(release:, canaries: [ host ]) }

    it "names the version and where to fetch it, nothing else, and marks the host as updating" do
      expect(directive(host)).to eq(
        rollout_id: rollout.id, version: "0.3.0",
        manifest_url: Releases.download_url("0.3.0", "manifest"), signature_url: Releases.download_url("0.3.0", "signature"),
        binary_url: Releases.download_url("0.3.0", "binary")
      )
      member = rollout.rollout_hosts.sole
      expect(member).to have_attributes(state: "updating", offered_at: be_present)
      first_offer = member.offered_at
      expect(directive(host)).to be_present # again on every heartbeat until a result arrives
      expect(member.reload.offered_at).to eq(first_offer)
    end

    it "validates against the contract" do
      expect(ApiContract.errors("heartbeat.response", "v1", { "server_time" => "2026-01-01T12:00:00Z", "directives" => { "agent_update" => directive(host).deep_stringify_keys } })).to eq([])
    end

    it "sends nothing to a host that already runs the release or newer, or an unreadable version" do
      expect(directive(host, "0.3.0")).to be_nil
      expect(directive(host, "0.4.0-rc.1")).to be_nil
      expect(directive(host, "garbage")).to be_nil
      expect(rollout.rollout_hosts.sole.state).to eq("pending")
    end

    it "sends a pre-release of the target to a host running an older version" do
      expect(directive(host, "0.3.0-rc.1")).to be_present
    end

    it "sends nothing before the host's offer time (the stage is spread over a window)" do
      member = rollout.rollout_hosts.sole
      member.update!(offer_at: 1.minute.from_now)
      expect(directive(host)).to be_nil
      travel_to(2.minutes.from_now) { expect(directive(host)).to be_present }
    end

    it "sends nothing to hosts outside the rollout, and nothing while it is halted, cancelled, or completed" do
      stranger, = host_running("0.2.0")
      expect(directive(stranger)).to be_nil
      Rollouts.halt!(rollout, actor: operator)
      expect(directive(host)).to be_nil
      Rollouts.resume!(rollout, actor: operator)
      expect(directive(host)).to be_present
      Rollouts.cancel!(rollout, actor: operator)
      expect(directive(host)).to be_nil
    end

    it "stops once the host has reported" do
      report(rollout, host, outcome: "failed", reason: "x")
      expect(directive(host)).to be_nil
    end

    it "spreads a stage over the configured window, one fixed offset per host" do
      Rails.configuration.x.rollouts.spread = 300
      Rollouts.cancel!(rollout, actor: operator)
      hosts = Array.new(6) { host_running("0.2.0").first }
      spread = start_rollout(release:, canaries: hosts)
      offsets = spread.rollout_hosts.map { |member| (member.offer_at - spread.started_at).round }
      expect(offsets).to all(be_between(0, 299))
      expect(offsets.uniq.size).to be > 1
      again = spread.rollout_hosts.map { |member| Rollouts.send(:offer_delay, spread, member.host_id).to_i }
      expect(again).to eq(offsets)
    end
  end

  describe ".record_result!" do
    let!(:host) { host_running("0.2.0").first }
    let!(:second) { host_running("0.2.0").first }
    let!(:rollout) { start_rollout(release:, canaries: [ host, second ]) }

    it "stores a success in the host's history, confirms the host, and audits it with the host as actor" do
      result = report(rollout, host, agent_version: "0.3.0", report_id: "00000000-0000-4000-8000-000000000001")
      expect(result).to have_attributes(report_id: "00000000-0000-4000-8000-000000000001", duplicate: false)
      expect(AgentUpdate.sole).to have_attributes(host:, rollout:, outcome: "succeeded", version: "0.3.0", reported_agent_version: "0.3.0",
                                                  occurred_at: Time.utc(2026, 1, 1, 12, 5), reason: nil)
      expect(rollout.rollout_hosts.find_by!(host:)).to have_attributes(state: "confirmed", resolved_at: be_present)
      expect(rollout.reload).to have_attributes(state: "running", current_stage: 0) # the other canary is still out
      entry = AuditEntry.find_by!(action: Audit::Actions::UPDATE_SUCCEEDED)
      expect(entry).to have_attributes(actor_type: "host", actor_id: host.id, target_type: "AgentUpdate")
    end

    it "treats a retried report_id as a duplicate and changes nothing" do
      report(rollout, host, report_id: "00000000-0000-4000-8000-000000000002")
      expect { expect(report(rollout, host, report_id: "00000000-0000-4000-8000-000000000002", outcome: "failed", reason: "late")).to have_attributes(duplicate: true) }
        .not_to change { [ AgentUpdate.count, AuditEntry.count, rollout.reload.state ] }
    end

    { "failed" => "failed", "rolled_back" => "rolled back" }.each do |outcome, words|
      it "halts the rollout when a host reports #{outcome}, and audits the outcome and the halt" do
        report(rollout, host, outcome:, reason: "no heartbeat\nwithin 5 minutes\t")
        expect(AgentUpdate.sole).to have_attributes(outcome:, reason: "no heartbeat within 5 minutes")
        expect(rollout.rollout_hosts.find_by!(host:).state).to eq(outcome)
        expect(rollout.reload).to have_attributes(state: "halted", halted_at: be_present, halted_by: nil, open_slot: 1)
        expect(rollout.halt_reason).to eq("#{host.name} reported #{words}: no heartbeat within 5 minutes")
        expect(audit_actions.last(2)).to eq([ "update.#{outcome}", Audit::Actions::ROLLOUT_HALTED ])
        halted = AuditEntry.find_by!(action: Audit::Actions::ROLLOUT_HALTED)
        expect(halted).to have_attributes(actor_type: "system")
        expect(halted.changeset).to include("state" => %w[running halted], "reason" => rollout.halt_reason)
      end
    end

    it "keeps a halted rollout halted until an operator resumes it, even if the other canary confirms" do
      report(rollout, host, outcome: "rolled_back", reason: "crash loop")
      report(rollout, second)
      expect(rollout.reload).to have_attributes(state: "halted", current_stage: 0)
      Rollouts.resume!(rollout, actor: operator)
      expect(rollout.reload).to have_attributes(state: "running", resumed_by: operator, resumed_at: be_present, current_stage: 0)
      expect(audit_actions).to include(Audit::Actions::ROLLOUT_RESUMED)
      resumed = AuditEntry.find_by!(action: Audit::Actions::ROLLOUT_RESUMED)
      expect(resumed).to have_attributes(actor_type: "operator", actor_id: operator.id)
      expect(resumed.changeset["reason"]).to include("crash loop")
    end

    it "records a result that arrives after the rollout stopped, without halting again" do
      Rollouts.cancel!(rollout, actor: operator)
      expect { report(rollout, host, outcome: "rolled_back", reason: "late") }.not_to change { audit_actions.count(Audit::Actions::ROLLOUT_HALTED) }
      expect(rollout.reload.state).to eq("cancelled")
      expect(AgentUpdate.sole.outcome).to eq("rolled_back")
    end

    it "confirms a host that was marked unconfirmed when its success arrives late" do
      member = rollout.rollout_hosts.find_by!(host:)
      member.update!(state: "unconfirmed")
      report(rollout, host)
      expect(member.reload.state).to eq("confirmed")
    end

    it "refuses an unknown rollout, a host outside the rollout, and another version" do
      stranger, = host_running("0.2.0")
      expect { report(rollout, host, rollout_id: 0) }.to raise_error(AgentApi::ValidationFailed) { |e| expect(e.details).to eq([ { "pointer" => "/rollout_id", "problem" => "No such rollout." } ]) }
      expect { report(rollout, stranger) }.to raise_error(AgentApi::ValidationFailed) { |e| expect(e.details.first["problem"]).to include("not part") }
      expect { report(rollout, host, version: "9.9.9") }.to raise_error(AgentApi::ValidationFailed) { |e| expect(e.details.first["pointer"]).to eq("/version") }
      expect(AgentUpdate.count).to eq(0)
    end

    it "truncates a long reason" do
      report(rollout, host, outcome: "failed", reason: "x" * 600)
      expect(AgentUpdate.sole.reason.length).to eq(Rollouts::REASON_LIMIT)
    end

    it "keeps the history read-only" do
      report(rollout, host)
      expect { AgentUpdate.sole.update!(outcome: "failed") }.to raise_error(ActiveRecord::ReadOnlyRecord)
    end
  end

  describe ".expire_unconfirmed!" do
    let!(:host) { host_running("0.2.0").first }
    let!(:rollout) { start_rollout(release:, canaries: [ host ]) }

    it "marks a host that never reported unconfirmed, halts the rollout, and audits both" do
      directive(host)
      expect(Rollouts.expire_unconfirmed!).to eq(0) # inside the timeout
      travel_to(Rails.configuration.x.rollouts.confirmation_timeout.from_now + 1.minute) do
        expect(Rollouts.expire_unconfirmed!).to eq(1)
        expect(Rollouts.expire_unconfirmed!).to eq(0) # idempotent
      end
      expect(rollout.rollout_hosts.sole.state).to eq("unconfirmed")
      expect(rollout.reload).to have_attributes(state: "halted", halted_by: nil)
      expect(rollout.halt_reason).to eq("1 host(s) did not confirm the update in time.")
      expect(audit_actions.last(2)).to eq([ Audit::Actions::UPDATE_UNCONFIRMED, Audit::Actions::ROLLOUT_HALTED ])
      expect(AuditEntry.find_by!(action: Audit::Actions::UPDATE_UNCONFIRMED).changeset).to include("host_id" => host.id, "version" => "0.3.0")
      expect(directive(host)).to be_nil
      Rollouts.resume!(rollout, actor: operator)
      expect(rollout.reload).to have_attributes(state: "running", current_stage: 0) # unconfirmed blocks advancing
    end

    it "ignores hosts never sent the directive, and rollouts that are not running" do
      travel_to(2.hours.from_now) { expect(Rollouts.expire_unconfirmed!).to eq(0) }
      directive(host)
      Rollouts.halt!(rollout, actor: operator)
      travel_to(2.hours.from_now) { expect(Rollouts.expire_unconfirmed!).to eq(0) }
      expect(rollout.rollout_hosts.sole.state).to eq("updating")
    end

    it "does nothing when the overdue hosts report between the scan and the lock" do
      directive(host)
      allow(Rollout).to receive(:transaction).and_wrap_original do |original, *args, &block|
        original.call(*args) { rollout.rollout_hosts.update_all(state: "confirmed"); block.call }
      end
      travel_to(2.hours.from_now) { expect(Rollouts.expire_unconfirmed!).to eq(0) }
      expect(rollout.reload.state).to eq("running")
    end

    it "runs from the recurring job" do
      directive(host)
      travel_to(2.hours.from_now) { RolloutTimeoutJob.perform_now }
      expect(rollout.reload.state).to eq("halted")
    end
  end

  describe "operator actions" do
    let!(:host) { host_running("0.2.0").first }
    let!(:rollout) { start_rollout(release:, canaries: [ host ]) }

    it "halts with an operator reason, resumes, and cancels, each audited with the operator" do
      Rollouts.halt!(rollout, actor: operator, reason: "holding for the weekend")
      expect(rollout.reload).to have_attributes(state: "halted", halted_by: operator, halt_reason: "holding for the weekend")
      expect { Rollouts.halt!(rollout, actor: operator) }.to raise_error(Rollouts::Invalid, /halted, not running/)
      expect { Rollouts.advance!(rollout, actor: operator) }.to raise_error(Rollouts::Invalid)
      Rollouts.resume!(rollout, actor: operator)
      expect { Rollouts.resume!(rollout, actor: operator) }.to raise_error(Rollouts::Invalid, /running, not halted/)
      Rollouts.cancel!(rollout, actor: operator)
      expect(rollout.reload).to have_attributes(state: "cancelled", open_slot: nil, finished_at: be_present)
      expect { Rollouts.cancel!(rollout, actor: operator) }.to raise_error(Rollouts::Invalid, /already cancelled/)
      expect(audit_actions.grep(/rollout\./)).to eq(%w[rollout.started rollout.halted rollout.resumed rollout.cancelled])
      expect(AuditEntry.where(action: Audit::Actions::ROLLOUT_CANCELLED).sole.changeset).to eq("state" => %w[running cancelled])
    end

    it "cancels a halted rollout" do
      Rollouts.halt!(rollout, actor: operator)
      Rollouts.cancel!(rollout, actor: operator)
      expect(rollout.reload.state).to eq("cancelled")
    end
  end
end
