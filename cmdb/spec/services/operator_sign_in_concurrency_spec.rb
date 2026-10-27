require "rails_helper"

# Two first sign-ins for the same Google account at once must both succeed with one operator record
# (review of #49). Runs outside the test transaction so each thread commits on its own connection.
RSpec.describe OperatorSignIn do
  self.use_transactional_tests = false

  after do
    operator_ids = Operator.where(google_uid: "1000000000099").pluck(:id)
    ActiveRecord::Base.connection.execute("SET session_replication_role = replica") # audit entries are append-only
    AuditEntry.where(actor_type: "operator", actor_id: operator_ids).delete_all
    AuditEntry.where(target_type: "OperatorAllowlistEntry", target_id: @entry_id).delete_all if @entry_id
    OperatorSession.where(operator_id: operator_ids).delete_all
    Operator.where(id: operator_ids).delete_all
    OperatorAllowlistEntry.where(email: "race@example.com").delete_all
  ensure
    ActiveRecord::Base.connection.execute("SET session_replication_role = DEFAULT")
  end

  it "creates one operator when the first sign-ins race" do
    @entry_id = allow_operator("race@example.com").id
    auth = google_auth(email: "race@example.com", uid: "1000000000099")
    gate = Concurrent::CountDownLatch.new(1)
    threads = Array.new(4) do # the test pool has 5 connections; this thread holds one
      Thread.new do
        gate.wait
        ActiveRecord::Base.connection_pool.with_connection { described_class.call(auth).id }
      rescue StandardError => e
        e
      end
    end
    gate.count_down
    results = threads.map(&:value)

    expect(results.grep(Exception)).to eq([])
    expect(results.uniq.size).to eq(1)
    expect(Operator.where(google_uid: "1000000000099").count).to eq(1)
    expect(AuditEntry.where(action: Audit::Actions::OPERATOR_SIGNED_IN, actor_id: results.first).count).to eq(4)
  end
end
