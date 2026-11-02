require "rails_helper"

# P1-UPDATES: a heartbeat offering an update and an operator's halt are serialised on the rollout row
# (Rollouts.directive_for reads it FOR SHARE; halt, cancel, and advance take it FOR UPDATE). Runs outside the test
# transaction so each thread commits on its own connection.
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

  it "makes a halt wait for a heartbeat that is already offering the update" do
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
    expect(halt.join(1)).to be_nil # blocked on the heartbeat's share lock
    release << :go
    heartbeat.join
    expect(halt.join(10)).to be_truthy
    expect(@rollout.reload.state).to eq("halted")
  ensure
    release << :go if release&.empty?
  end

  it "makes a heartbeat that arrives during a halt wait, then offer nothing" do
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

    heartbeat = Thread.new { offer }
    expect(heartbeat.join(1)).to be_nil # waits for the halt to commit
    release << :go
    halting.join
    expect(heartbeat.join(10)&.value).to be_nil # re-read the row: halted, so no directive
    expect(@rollout.rollout_hosts.sole.state).to eq("pending")
    expect(AuditEntry.where(action: Audit::Actions::UPDATE_REQUESTED)).to be_empty
  ensure
    release << :go if release&.empty?
  end
end
