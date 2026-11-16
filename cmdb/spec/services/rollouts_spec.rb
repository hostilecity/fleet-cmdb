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

  # The offer offset Rollouts::OFFER_DELAY_SQL gives a host, in seconds.
  def offer_offset(rollout, host_id, spread)
    sql = Rollouts::OFFER_DELAY_SQL.sub("hosts.id", "?::bigint")
    ActiveRecord::Base.connection.select_value(ActiveRecord::Base.sanitize_sql_array([ "SELECT EXTRACT(EPOCH FROM #{sql})::int", rollout.id, host_id, spread ]))
  end

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

  describe "default stages (#199)" do
    it "keeps 25 and 100 percent for a homelab, and uses 1, 10, 50, and 100 from 1,000 active hosts" do
      expect(Rollouts.default_stages(50)).to eq([ 25, 100 ])
      expect(Rollouts.default_stages(999)).to eq([ 25, 100 ])
      expect(Rollouts.default_stages(1_000)).to eq([ 1, 10, 50, 100 ])
      expect(Rollouts.default_stages(1_000_000)).to eq([ 1, 10, 50, 100 ])
    end

    it "uses FLEET_ROLLOUT_LARGE_FLEET_HOSTS as the threshold" do
      Rails.configuration.x.rollouts.large_fleet_hosts = 50_000
      expect(Rollouts.default_stages(49_999)).to eq([ 25, 100 ])
      expect(Rollouts.default_stages(50_000)).to eq([ 1, 10, 50, 100 ])
    end

    # Loads config/initializers/rollouts.rb with the setting as given (nil: unset) and returns the value it sets.
    def boot_with(setting, key, value)
      saved = ENV.fetch(setting, nil)
      ENV[setting] = value
      Rails.configuration.x.rollouts.delete(key)
      load Rails.root.join("config/initializers/rollouts.rb")
      Rails.configuration.x.rollouts.public_send(key)
    ensure
      ENV[setting] = saved
    end

    describe "FLEET_ROLLOUT_LARGE_FLEET_HOSTS" do
      def boot(value) = boot_with("FLEET_ROLLOUT_LARGE_FLEET_HOSTS", :large_fleet_hosts, value)

      it "is 1,000 hosts by default, and otherwise a whole number from 1 to 100,000,000" do
        expect(boot(nil)).to eq(1_000)
        expect(boot("250")).to eq(250)
        expect(boot("1")).to eq(1)
        expect(boot("100000000")).to eq(100_000_000)
      end

      it "stops the server at boot, naming the setting, for anything else, an empty value included" do
        [ "", "0", "-5", "100000001", "1.5", "1e3", "1,000", "abc" ].each do |value|
          expect { boot(value) }
            .to raise_error(RuntimeError, "FLEET_ROLLOUT_LARGE_FLEET_HOSTS must be a whole number of hosts from 1 to 100000000 (got #{value.inspect})")
        end
      end
    end

    describe "FLEET_ROLLOUT_DOWNLOADS_PER_SECOND" do
      def boot(value) = boot_with("FLEET_ROLLOUT_DOWNLOADS_PER_SECOND", :downloads_per_second, value)

      it "is 10 by default, and otherwise a whole number from 1 to 100,000" do
        expect(boot(nil)).to eq(10)
        expect(boot("1")).to eq(1)
        expect(boot("250")).to eq(250)
        expect(boot("100000")).to eq(100_000)
      end

      it "stops the server at boot, naming the setting, for anything else (it used to turn 0 into 1)" do
        [ "", "0", "-1", "100001", "2.5", "ten" ].each do |value|
          expect { boot(value) }
            .to raise_error(RuntimeError, "FLEET_ROLLOUT_DOWNLOADS_PER_SECOND must be a whole number of downloads a second from 1 to 100000 (got #{value.inspect})")
        end
      end
    end

    it "chooses them by the fleet's active hosts when a rollout starts without stages" do
      canary, = host_running("0.2.0")
      host_running("0.3.0")
      Rails.configuration.x.rollouts.large_fleet_hosts = 2 # two active hosts
      expect(start_rollout(release:, canaries: [ canary ]).stage_percents).to eq([ 1, 10, 50, 100 ])
    end
  end

  describe "opening a stage in batches (#199)" do
    it "chooses the same hosts, in host id order, however small the batch, and inserts a batch at a time" do
      canary, = host_running("0.2.0")
      others = Array.new(9) { host_running("0.2.0").first }
      host_running("0.3.0") # already on the release: never chosen
      stub_const("Rollouts::OPEN_BATCH", 2)
      rollout = start_rollout(release:, canaries: [ canary ], stage_percents: [ 50, 100 ])
      inserts = []
      callback = ->(*, payload) { inserts << payload[:sql] if payload[:sql].start_with?("WITH batch AS") }
      ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { Rollouts.advance!(rollout, actor: operator) }
      # 50% of the 10 older hosts is 5; the canary is one, so 4 more, the lowest ids. Each statement scans 2 older
      # hosts whatever is still wanted (review of #215): the canary's pair adds 1, then 2, then 2, of which the extra
      # one, the highest id, is deleted again.
      expect(rollout.rollout_hosts.where(stage: 1).order(:host_id).pluck(:host_id)).to eq(others.map(&:id).sort.first(4))
      expect(inserts.size).to eq(3)
      ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { Rollouts.advance!(rollout, actor: operator) }
      expect(rollout.rollout_hosts.count).to eq(10)
      expect(rollout.rollout_hosts.pluck(:host_id).uniq.size).to eq(10)
      expect(inserts.size).to eq(9) # the 100% stage is not capped: all 10 older hosts in pairs, then an empty scan
    end

    it "chooses the next stage's hosts before it takes the rollout lock, and shows them only once the stage opens" do
      canary, = host_running("0.2.0")
      Array.new(3) { host_running("0.2.0") }
      rollout = start_rollout(release:, canaries: [ canary ], stage_percents: [ 50, 100 ])
      statements = []
      callback = ->(*, payload) { statements << payload[:sql] }
      ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { Rollouts.advance!(rollout, actor: operator) }
      first_insert = statements.index { |sql| sql.start_with?("WITH batch AS") }
      lock = statements.index { |sql| sql.include?('FROM "rollouts"') && sql.include?("FOR UPDATE") }
      expect(first_insert).to be < lock
      expect(rollout.reload.current_stage).to eq(1)
    end

    it "keeps a canary tag a query: no tagged host id is read into Ruby" do
      tagged = Array.new(3) { host_running("0.2.0", tags: [ "canary" ]).first }
      host_running("0.2.0")
      statements = []
      callback = ->(*, payload) { statements << payload[:sql] }
      rollout = ActiveSupport::Notifications.subscribed(callback, "sql.active_record") do
        Rollouts.start!(release:, actor: operator, canary_tag: "canary")
      end
      expect(rollout.rollout_hosts.pluck(:host_id)).to match_array(tagged.map(&:id))
      expect(statements.grep(/WITH batch AS/)).to all(include("tags @>"))
      expect(statements.grep(/SELECT "hosts"."id" FROM "hosts"/)).to be_empty
    end
  end

  describe "the prepare lock (review of #215)" do
    let!(:canary) { host_running("0.2.0").first }
    let!(:rollout) { start_rollout(release:, canaries: [ canary ], stage_percents: [ 100 ]) }

    def held = ActiveRecord::Base.connection.select_value(
      "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND classid = #{Rollouts::PREPARE_LOCK_KEY} AND objid = #{rollout.id} AND pid = pg_backend_pid()"
    )

    it "is released after the prepare, also when the prepare fails" do
      Rollouts.send(:prepare_stage!, rollout, 1)
      expect(held).to eq(0)
      allow(Rollouts).to receive(:insert_stage_rows!).and_raise("boom")
      expect { Rollouts.send(:prepare_stage!, rollout, 1) }.to raise_error("boom")
      expect(held).to eq(0)
    end

    it "closes the connection when the lock cannot be released, so the lock goes with it" do
      connection = Rollout.connection
      allow(connection).to receive(:select_value).and_call_original
      allow(connection).to receive(:select_value).with(/pg_advisory_unlock/).and_raise(ActiveRecord::ConnectionFailed)
      allow(connection).to receive(:throw_away!)
      Rollouts.send(:prepare_stage!, rollout, 1)
      expect(connection).to have_received(:throw_away!)
    ensure
      connection&.execute("SELECT pg_advisory_unlock_all()") # throw_away! was stubbed, so the test's connection still holds it
    end
  end

  describe "the advance after a confirmed stage (#199)" do
    include ActiveJob::TestHelper

    it "runs in RolloutAdvanceJob after the confirming result commits, not inside it", rollout_jobs: :enqueued do
      canary, = host_running("0.2.0")
      Array.new(3) { host_running("0.2.0") }
      rollout = start_rollout(release:, canaries: [ canary ])
      report(rollout, canary)
      expect(rollout.reload.current_stage).to eq(0)
      expect(rollout.rollout_hosts.count).to eq(1) # nothing chosen under the update result's transaction
      expect(enqueued_jobs.map { |job| [ job["job_class"], job["arguments"] ] }).to include([ "RolloutAdvanceJob", [ rollout.id, 0 ] ])
      perform_enqueued_jobs(only: RolloutAdvanceJob)
      expect(rollout.reload.current_stage).to eq(1)
      # A repeated or late job does nothing.
      expect { Rollouts.advance_confirmed!(rollout.id, from: 0) }.not_to(change { rollout.reload.attributes })
      expect { Rollouts.advance_confirmed!(0, from: 0) }.not_to raise_error
    end

    it "is enqueued again by RolloutTimeoutJob every minute if the job was lost, never prepared on its queue", rollout_jobs: :enqueued do
      canary, = host_running("0.2.0")
      Array.new(3) { host_running("0.2.0") }
      rollout = start_rollout(release:, canaries: [ canary ], stage_percents: [ 50, 100 ]) # stage 1: one more host
      report(rollout, canary)
      clear_enqueued_jobs
      statements = []
      callback = ->(*, payload) { statements << payload[:sql] }
      ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { RolloutTimeoutJob.perform_now }
      expect(statements.grep(/INSERT INTO rollout_hosts|pg_try_advisory_lock/)).to be_empty # the realtime queue only enqueues (S-7)
      expect(rollout.reload.current_stage).to eq(0)
      expect(enqueued_jobs.map { |job| [ job["job_class"], job["arguments"], job["queue_name"] ] }).to eq([ [ "RolloutAdvanceJob", [ rollout.id, 0 ], "default" ] ])
      perform_enqueued_jobs(only: RolloutAdvanceJob)
      expect(rollout.reload.current_stage).to eq(1)
      clear_enqueued_jobs
      RolloutTimeoutJob.perform_now # an unconfirmed stage enqueues nothing
      expect(enqueued_jobs).to be_empty
    end

    it "does not advance a rollout that halted, or an operator moved on, before the job ran", rollout_jobs: :enqueued do
      canary, = host_running("0.2.0")
      host_running("0.2.0")
      rollout = start_rollout(release:, canaries: [ canary ])
      report(rollout, canary)
      Rollouts.halt!(rollout, actor: operator)
      perform_enqueued_jobs(only: RolloutAdvanceJob)
      expect(rollout.reload).to have_attributes(state: "halted", current_stage: 0)
    end
  end

  describe "halts and the spread window (#199)" do
    before do
      Rails.configuration.x.rollouts.spread = 300
    end

    it "keeps a stage's offers spread over what is left of its window after a halt longer than the window" do
      hosts = Array.new(40) { host_running("0.2.0").first }
      t0 = Time.current.change(usec: 0)
      travel_to(t0)
      rollout = start_rollout(release:, canaries: hosts)
      due = ->(at) { hosts.count { |host| Rollouts.offer_scope(host_id: host.id, now: at).exists? } }
      offsets = rollout.rollout_hosts.to_h { |member| [ member.host_id, member.offer_at - t0 ] }
      travel_to(t0 + 10.seconds)
      Rollouts.halt!(rollout, actor: operator)
      travel_to(t0 + 10.seconds + 1.hour)
      Rollouts.resume!(rollout.reload, actor: operator)
      expect(rollout.reload.halted_seconds).to eq(3600)
      # Only the offers due before the halt are due now, not the whole stage.
      expect(due.(Time.current)).to eq(offsets.values.count { |offset| offset <= 10 })
      expect(due.(Time.current)).to be < 40
      # The rest follow over the 290 seconds the window had left.
      expect(due.(Time.current + 150.seconds)).to eq(offsets.values.count { |offset| offset <= 160 })
      expect(due.(Time.current + 290.seconds)).to eq(40)
    end

    it "re-times a stage prepared for an advance that was refused, so its offers stay spread when it opens" do
      canary, = host_running("0.2.0")
      hosts = Array.new(40) { host_running("0.2.0").first }
      t0 = Time.current.change(usec: 0)
      travel_to(t0)
      rollout = start_rollout(release:, canaries: [ canary ], stage_percents: [ 100 ])
      Rollouts.send(:prepare_stage!, rollout, 1) # chosen, then the advance was refused (a halt committed meanwhile)
      Rollouts.halt!(rollout, actor: operator)
      travel_to(t0 + 1.hour)
      Rollouts.resume!(rollout.reload, actor: operator)
      travel_to(t0 + 7.hours)
      Rollouts.advance!(rollout.reload, actor: operator)
      expect(rollout.reload.current_stage).to eq(1)
      due = ->(at) { hosts.count { |host| Rollouts.offer_scope(host_id: host.id, now: at).exists? } }
      expect(due.(Time.current)).to be < 40 # not every offer due the moment the stage opens
      expect(due.(Time.current + 300.seconds)).to eq(40)
    end

    it "sizes the 100% stage's window from the hosts it adds, not the older hosts already in the rollout" do
      Rails.configuration.x.rollouts.spread = 1
      Rails.configuration.x.rollouts.downloads_per_second = 1
      canary, = host_running("0.2.0")
      Array.new(9) { host_running("0.2.0") }
      rollout = start_rollout(release:, canaries: [ canary ], stage_percents: [ 50, 100 ])
      Rollouts.advance!(rollout, actor: operator) # stage 1: 5 of the 10 hosts, still pending (older)
      allow(Rollouts).to receive(:stage_spread).and_call_original
      Rollouts.advance!(rollout.reload, actor: operator)
      expect(Rollouts).to have_received(:stage_spread).with(5) # the 5 added, not the 10 older hosts
      offsets = rollout.rollout_hosts.where(stage: 2).map { |member| (member.offer_at + rollout.reload.halted_seconds - member.created_at).round }
      expect(offsets).to all(be_between(0, 4))
    end

    it "does not delay a stage opened after a halt by the time halted before it" do
      canary, = host_running("0.2.0")
      host_running("0.2.0")
      t0 = Time.current.change(usec: 0)
      travel_to(t0)
      rollout = start_rollout(release:, canaries: [ canary ], stage_percents: [ 100 ])
      Rollouts.halt!(rollout, actor: operator)
      travel_to(t0 + 1.hour)
      Rollouts.resume!(rollout.reload, actor: operator)
      Rollouts.advance!(rollout.reload, actor: operator)
      member = rollout.rollout_hosts.find_by!(stage: 1)
      offset = (member.offer_at + rollout.reload.halted_seconds - Time.current).round
      expect(offset).to be_between(0, 299)
      expect(Rollouts.offer_scope(host_id: member.host_id, now: Time.current + 300.seconds).exists?).to be(true)
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

    it "does not complete while hosts of an earlier stage are still pending or updating, and completes when they confirm" do
      Rollouts.advance!(rollout, actor: operator)
      Rollouts.advance!(rollout, actor: operator)
      expect(rollout.reload.current_stage).to eq(2)
      early = rollout.rollout_hosts.where(stage: [ 0, 1 ]).includes(:host).to_a
      rollout.rollout_hosts.where(stage: 2).includes(:host).find_each { |member| report(rollout, member.host) }
      expect(rollout.reload.state).to eq("running") # the final stage confirmed, but earlier hosts have not
      early.first.update!(state: "updating")
      expect(directive(early.first.host)).to be_present # still offered, and still timed out if it never reports
      early.each { |member| report(rollout, member.host) }
      expect(rollout.reload.state).to eq("completed")
    end

    it "halts on a late failure from an earlier stage after an operator advanced to the final stage" do
      Rollouts.advance!(rollout, actor: operator)
      Rollouts.advance!(rollout, actor: operator)
      rollout.rollout_hosts.where(stage: 2).includes(:host).find_each { |member| report(rollout, member.host) }
      report(rollout, canary, outcome: "rolled_back", reason: "health check failed")
      expect(rollout.reload).to have_attributes(state: "halted", halt_reason: /rolled back/)
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

    it "audits the request for the host once, on the first offer, not on repeat heartbeats" do
      2.times { directive(host) }
      entry = AuditEntry.where(action: Audit::Actions::UPDATE_REQUESTED).sole
      expect(entry).to have_attributes(actor_type: "system", target_type: "Host", target_id: host.id)
      expect(entry.changeset).to eq("rollout_id" => rollout.id, "version" => "0.3.0")
    end

    it "keeps the request on the host's audit trail when the rollout is cancelled before a result" do
      directive(host)
      Rollouts.cancel!(rollout, actor: operator)
      expect(AuditEntry.where(target_type: "Host", target_id: host.id).pluck(:action)).to include(Audit::Actions::UPDATE_REQUESTED)
    end

    it "locks the rollout only for a host's first offer, FOR SHARE SKIP LOCKED (#199; spec/services/rollout_concurrency_spec.rb)" do
      locks = ->(&block) {
        queries = []
        callback = ->(*, payload) { queries << payload[:sql] if payload[:sql].match?(/\bFOR (SHARE|UPDATE|NO KEY UPDATE|KEY SHARE)\b/) }
        ActiveSupport::Notifications.subscribed(callback, "sql.active_record", &block)
        queries
      }
      first = locks.() { directive(host) }
      expect(first.size).to eq(1)
      expect(first.first).to include('FROM "rollouts"').and(include("FOR SHARE SKIP LOCKED"))
      expect(locks.() { directive(host) }).to be_empty # a repeat to a host already updating
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

    it "spreads a large stage over a longer window, so downloads come at most about the configured rate (#199)" do
      Rails.configuration.x.rollouts.spread = 300
      Rails.configuration.x.rollouts.downloads_per_second = 2
      expect(Rollouts.stage_spread(10)).to eq(300)
      expect(Rollouts.stage_spread(600)).to eq(300)
      expect(Rollouts.stage_spread(601)).to eq(301)
      expect(Rollouts.stage_spread(750_000)).to eq(375_000)
      Rails.configuration.x.rollouts.spread = 1
      Rollouts.cancel!(rollout, actor: operator)
      hosts = Array.new(6) { host_running("0.2.0").first }
      spread = start_rollout(release:, canaries: hosts) # 6 hosts at 2 a second: 3 seconds
      offsets = spread.rollout_hosts.map { |member| (member.offer_at - spread.started_at).round }
      expect(offsets).to all(be_between(0, 2))
      expect(offsets).to eq(spread.rollout_hosts.map { |member| offer_offset(spread, member.host_id, 3) })
    end

    it "spreads a stage over the configured window, one fixed offset per host" do
      Rails.configuration.x.rollouts.spread = 300
      Rollouts.cancel!(rollout, actor: operator)
      hosts = Array.new(6) { host_running("0.2.0").first }
      spread = start_rollout(release:, canaries: hosts)
      offsets = spread.rollout_hosts.map { |member| (member.offer_at - spread.started_at).round }
      expect(offsets).to all(be_between(0, 299))
      expect(offsets.uniq.size).to be > 1
      again = spread.rollout_hosts.map { |member| offer_offset(spread, member.host_id, 300) }
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
