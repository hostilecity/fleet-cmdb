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
end
