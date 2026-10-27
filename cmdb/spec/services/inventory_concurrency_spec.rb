require "rails_helper"

# DEC-07, AC-1.4: a report retried while the first attempt is still in flight is processed exactly once.
# Runs outside the test transaction so each thread commits on its own connection.
RSpec.describe InventoryRecorder do
  self.use_transactional_tests = false

  after do
    ActiveRecord::Base.connection.execute("SET session_replication_role = replica") # hosts and audit are protected
    [ InventorySnapshot, HostInventory, InventoryReportReceipt, AgentCredential, EnrollmentToken ].each { |model| model.where(host_id: @host.id).delete_all }
    AuditEntry.where(target_type: "Host", target_id: @host.id).delete_all
    Host.where(id: @host.id).delete_all
  ensure
    ActiveRecord::Base.connection.execute("SET session_replication_role = DEFAULT")
  end

  it "processes one of several identical reports sent at once and answers the rest as duplicates" do
    @host, credential = enrolled_host(hostname: "race.example.lan")
    credential_id = @host.agent_credentials.active.pick(:id)
    payload = ApiContract.examples.find { |e| e.schema_name == "inventory.request" && e.name == "full" }.data
    report = AgentApi::InventoryReport.new(payload)
    expect(credential).to be_present

    gate = Concurrent::CountDownLatch.new(1)
    threads = Array.new(4) do # the test pool has 5 connections; this thread holds one
      Thread.new do
        gate.wait
        ActiveRecord::Base.connection_pool.with_connection do
          HostInventory.transaction { described_class.record!(host_id: @host.id, credential_id:, report:).duplicate }
        end
      end
    end
    gate.count_down
    duplicates = threads.map(&:value)

    expect(duplicates.count(false)).to eq(1)
    expect(duplicates.count(true)).to eq(3)
    expect(InventorySnapshot.where(host_id: @host.id).count).to eq(1)
    expect(InventoryReportReceipt.where(host_id: @host.id).count).to eq(1)
  end
end
