require "rails_helper"

# AgentHostLock reads the host and the credential in one statement (#189). A revocation, retirement, or re-enrollment
# that holds the host row when an agent write arrives must still be seen once the write gets the lock, and the two
# must never deadlock (lock order: host, then credential). Runs outside the test transaction so each thread commits
# on its own connection.
RSpec.describe AgentHostLock do
  self.use_transactional_tests = false

  after do
    ActiveRecord::Base.connection.execute("SET session_replication_role = replica") # hosts and audit are protected
    [ AgentCredential, EnrollmentToken ].each { |model| model.where(host_id: @host.id).delete_all }
    AuditEntry.where(target_type: "Host", target_id: @host.id).delete_all
    Host.where(id: @host.id).delete_all
  ensure
    ActiveRecord::Base.connection.execute("SET session_replication_role = DEFAULT")
  end

  # Runs change in a transaction that holds the host row until the agent write is waiting for it, then runs later
  # (still holding the lock) and commits. Returns the write's outcome: the host, or the Refused reason.
  def write_during(later: nil, &change)
    @host, = enrolled_host(hostname: "lock-race.example.lan")
    credential_id = @host.agent_credentials.active.pick(:id)
    @before_race&.call(@host)
    changed = Queue.new
    release = Queue.new
    operator = Thread.new do
      ActiveRecord::Base.connection_pool.with_connection do
        Host.transaction do
          host = Host.lock.find(@host.id)
          change.call(host)
          changed << true
          release.pop
          later&.call(host)
        end
      end
    end
    changed.pop
    write = Thread.new do
      ActiveRecord::Base.connection_pool.with_connection do
        Host.transaction { described_class.lock!(host_id: @host.id, credential_id:) }
      rescue AgentHostLock::Refused => e
        e.reason
      end
    end
    expect(write.join(0.5)).to be_nil # waiting for the host row
    release << :go
    operator.join(10)
    write.join(10).value
  ensure
    release << :go if release&.empty?
  end

  it "refuses a write that waited for a revocation, with the credential's committed state" do
    expect(write_during { |host| host.revoke!(actor: Audit::SYSTEM) }).to eq(:unauthorized)
  end

  it "refuses a write that waited for a retirement" do
    expect(write_during { |host| host.retire!(actor: Audit::SYSTEM) }).to eq(:unauthorized)
  end

  it "tells a write that waited for a re-enrollment to redeem the new token" do
    expect(write_during { |host| host.begin_reenrollment!(actor: Audit::SYSTEM) }).to eq(:reenrollment_required)
  end

  it "refuses the old credential's write that waited for a re-enrollment to complete (AC-1.5)" do
    @before_race = ->(host) { host.begin_reenrollment!(actor: Audit::SYSTEM) }
    result = write_during { |host| host.enroll!(machine_id: nil, agent_version: "0.1.0", schema_version: 1) }
    expect(result).to eq(:unauthorized) # the host is active again, but with a new credential
  end

  it "never deadlocks with a change that takes the host and then the credential while the write waits" do
    result = write_during(later: ->(host) { host.agent_credentials.active.lock.to_a.each(&:revoke!) }) { |_host| nil }
    expect(result).to eq(:unauthorized)
  end

  it "lets a write through once an unrelated change to the host commits" do
    result = write_during { |host| host.edit!({ notes: "changed meanwhile" }, actor: Audit::SYSTEM) }
    expect(result).to be_a(Host)
    expect(result.notes).to eq("changed meanwhile")
  end
end
