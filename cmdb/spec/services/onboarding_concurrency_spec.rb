require "rails_helper"

# P1-ONBOARD: "exactly one credential, even under concurrent collect attempts", and the open-request caps
# hold under concurrent starts. Deterministic: one thread holds its transaction open at the critical point
# while the other runs, so these fail without the locks. Runs outside the test transaction so each thread
# commits on its own connection.
RSpec.describe "Concurrent onboarding" do
  self.use_transactional_tests = false

  let(:operator) { create(:operator) }

  after do
    conn = ActiveRecord::Base.connection
    conn.execute("SET session_replication_role = replica") # hosts and audit entries are protected
    host_ids = Host.where(hostname: "vm-01.example.lan").pluck(:id)
    AuditEntry.where(target_type: "Host", target_id: host_ids).or(AuditEntry.where(target_type: "OnboardingRequest")).delete_all
    OnboardingRequest.delete_all
    AgentCredential.where(host_id: host_ids).delete_all
    Host.where(id: host_ids).delete_all
    Operator.where(id: operator.id).delete_all
  ensure
    ActiveRecord::Base.connection.execute("SET session_replication_role = DEFAULT")
  end

  def in_thread(&block)
    Thread.new { ActiveRecord::Base.connection_pool.with_connection(&block) }
  end

  it "issues one credential when two collects race for the same approved request" do
    started = start_onboarding
    Onboarding::Approve.call(request: started.record, operator:, attributes: { name: "Race" })
    inside = Queue.new
    release = Queue.new
    allow(AgentCredential).to receive(:issue!).and_wrap_original do |original, **args|
      if Thread.current[:hold]
        inside << true
        release.pop # hold the request's row lock while the second collect runs
      end
      original.call(**args)
    end

    first = in_thread do
      Thread.current[:hold] = true
      ApplicationRecord.transaction { collect_onboarding(started.device_code).status }
    end
    inside.pop
    second = in_thread do
      ApplicationRecord.transaction { collect_onboarding(started.device_code).status }
    rescue AgentApi::OnboardingExpired
      :expired
    end
    expect(second.join(0.5)).to be_nil # waits on the lock instead of issuing a second credential
    release << :go

    expect([ first.value, second.value ]).to eq([ :approved, :expired ])
    expect(Host.where(hostname: "vm-01.example.lan").count).to eq(1)
    expect(AgentCredential.where(host: Host.where(hostname: "vm-01.example.lan")).count).to eq(1)
  ensure
    release << :go if release&.empty?
  end

  it "keeps the per-address cap when starts race" do
    allow(OnboardingRequest.config).to receive(:max_open_per_address).and_return(1)
    held = Queue.new
    release = Queue.new
    first = in_thread do
      ApplicationRecord.transaction do
        start_onboarding
        held << true
        release.pop # the new request is not committed yet
      end
      :created
    end
    held.pop
    second = in_thread do
      start_onboarding
      :created
    rescue AgentApi::RateLimited
      :refused
    end
    expect(second.join(0.5)).to be_nil # serialised by the advisory lock rather than counting uncommitted rows
    release << :go

    expect([ first.value, second.value ]).to eq([ :created, :refused ])
    expect(OnboardingRequest.count).to eq(1)
  ensure
    release << :go if release&.empty?
  end
end
