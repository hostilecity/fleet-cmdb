require "rails_helper"

# P1-UPDATES, #199: Rollouts.directive_for reads the rollout without a lock, except for a host's first offer, which
# takes it FOR SHARE SKIP LOCKED. So no heartbeat waits, a halt waits only for first offers in flight, and once a halt
# or cancel commits no host is offered the update. Runs outside the test transaction so each thread commits on its
# own connection.
RSpec.describe "Concurrent rollout offers and halts" do
  self.use_transactional_tests = false

  let(:operator) { create(:operator) }

  before do
    @host, = host_running("0.2.0", hostname: "race-rollout.example.lan")
    @rollout = start_rollout(release: release_for_rollout("0.3.0"), canaries: [ @host ], operator:)
  end

  after do
    connection = ActiveRecord::Base.connection
    connection.execute("SET session_replication_role = replica") # audit, releases, and hosts are protected
    [ AgentUpdate, RolloutHost, Rollout, AgentRelease, AgentReleaseImport, AuditEntry, HostStatusEvent, AgentCredential, EnrollmentToken, Host, Operator ].each(&:delete_all)
  ensure
    connection&.execute("SET session_replication_role = DEFAULT")
  end

  def offer
    ActiveRecord::Base.connection_pool.with_connection do
      Host.transaction { Rollouts.directive_for(host_id: @host.id, agent_version: "0.2.0") }
    end
  end

  it "makes a halt wait for a heartbeat that is making a host's first offer" do
    offered = Queue.new
    release = Queue.new
    heartbeat = Thread.new do
      ActiveRecord::Base.connection_pool.with_connection do
        Host.transaction do
          offered << Rollouts.directive_for(host_id: @host.id, agent_version: "0.2.0")
          release.pop # the heartbeat's transaction is still open
        end
      end
    end
    expect(offered.pop).to be_present

    halt = Thread.new { ActiveRecord::Base.connection_pool.with_connection { Rollouts.halt!(Rollout.find(@rollout.id), actor: operator) } }
    expect(halt.join(1)).to be_nil # blocked on the first offer's share lock
    release << :go
    heartbeat.join
    expect(halt.join(10)).to be_truthy
    expect(@rollout.reload.state).to eq("halted")
  ensure
    release << :go if release&.empty?
  end

  it "does not make a heartbeat wait for a halt in progress, and offers nothing then or after it commits" do
    locked = Queue.new
    release = Queue.new
    halting = Thread.new do
      ActiveRecord::Base.connection_pool.with_connection do
        Rollout.transaction do
          Rollouts.halt!(Rollout.find(@rollout.id), actor: operator)
          locked << :halted
          release.pop # the halt has not committed yet
        end
      end
    end
    locked.pop

    # The first offer skips the locked row (SKIP LOCKED): no wait, and no directive (review of #215).
    during = Thread.new { offer }
    expect(during.join(10)).to be_truthy
    expect(during.value).to be_nil
    release << :go
    halting.join

    expect(@rollout.reload.state).to eq("halted")
    expect(offer).to be_nil
    expect(@rollout.rollout_hosts.sole.state).to eq("pending")
    expect(AuditEntry.where(action: Audit::Actions::UPDATE_REQUESTED)).to be_empty
  ensure
    release << :go if release&.empty?
  end

  it "offers nothing once a cancel commits, so no host installs a release the operator cancelled" do
    Rollouts.cancel!(Rollout.find(@rollout.id), actor: operator)
    expect(offer).to be_nil
    expect(@rollout.rollout_hosts.sole.state).to eq("pending")
  end

  describe "two prepares of the same stage at once (review of #215)" do
    # Ten more hosts on the old version, and stages [10, 100]: stage 1 brings the rollout to 2 of its 11 hosts.
    before do
      @others = Array.new(10) { |i| host_running("0.2.0", hostname: "race-stage-#{i}.example.lan").first }
      Rollout.find(@rollout.id).update_columns(stage_percents: [ 10, 100 ])
      @rollout.rollout_hosts.sole.update_columns(state: "confirmed")
      stub_const("Rollouts::OPEN_BATCH", 2)
    end

    # Runs `second` while the first advance is inside its prepare, holding the prepare lock.
    def with_a_prepare_in_progress(second)
      inside = Queue.new
      go = Queue.new
      allow(Rollouts).to receive(:insert_stage_rows!).and_wrap_original do |original, *args, **kwargs|
        if Thread.current[:first_prepare]
          inside << :in
          go.pop
        end
        original.call(*args, **kwargs)
      end
      first = Thread.new do
        Thread.current[:first_prepare] = true
        ActiveRecord::Base.connection_pool.with_connection { Rollouts.advance_confirmed!(@rollout.id, from: 0) }
      end
      inside.pop
      result = Thread.new { ActiveRecord::Base.connection_pool.with_connection { second.call } }.value
      go << :go
      first.join(10)
      result
    ensure
      go << :go if go&.empty?
    end

    it "lets one of them choose the stage: the other does nothing, and the stage keeps its exact size" do
      second = with_a_prepare_in_progress(-> { Rollouts.advance_confirmed!(@rollout.id, from: 0) })
      expect(second).to be_nil
      rollout = Rollout.find(@rollout.id)
      expect(rollout.current_stage).to eq(1)
      expect(rollout.rollout_hosts.where(stage: 1).count).to eq(1)
      expect(rollout.rollout_hosts.count).to eq(2) # ceil(11 * 10%) = 2: the canary and one more
      expect(AuditEntry.where(action: Audit::Actions::ROLLOUT_ADVANCED).count).to eq(1)
    end

    it "refuses an operator's advance while the stage is being chosen, and chooses it once" do
      advance = lambda do
        Rollouts.advance!(Rollout.find(@rollout.id), actor: operator)
      rescue Rollouts::Invalid => e
        e.message
      end
      second = with_a_prepare_in_progress(advance)
      expect(second).to eq("The next stage's hosts are being chosen right now. Try again in a minute.")
      expect(Rollout.find(@rollout.id).rollout_hosts.count).to eq(2)
    end
  end
end
