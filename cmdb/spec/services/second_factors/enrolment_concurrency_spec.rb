require "rails_helper"

# Two submits of one pending key at once (review of #165): only one sets up the factor and gets recovery codes; the
# other finds the key consumed. Runs outside the test transaction so each thread commits on its own connection.
RSpec.describe "SecondFactors.complete_enrolment! under concurrency" do
  self.use_transactional_tests = false

  after do
    ActiveRecord::Base.connection.execute("SET session_replication_role = replica") # audit entries are append-only
    AuditEntry.where(actor_type: "operator", actor_id: @operator.id).delete_all
    SecondFactor.where(operator_id: @operator.id).destroy_all
    OperatorSession.where(operator_id: @operator.id).delete_all
    @operator.delete
  ensure
    ActiveRecord::Base.connection.execute("SET session_replication_role = DEFAULT")
  end

  it "lets one of four submits of the same key through, and issues one set of recovery codes" do
    @operator = create(:operator)
    session = OperatorSession.start!(@operator).first
    key = SecondFactors.begin_enrolment!(session)
    code = totp_code(key)
    gate = Concurrent::CountDownLatch.new(1)
    threads = Array.new(4) do
      Thread.new do
        gate.wait
        ActiveRecord::Base.connection_pool.with_connection do
          SecondFactors.complete_enrolment!(OperatorSession.find(session.id), code).first
        end
      rescue StandardError => e
        e
      end
    end
    gate.count_down

    expect(threads.map(&:value).tally).to eq(enrolled: 1, expired: 3)
    factor = SecondFactor.find_by!(operator: @operator)
    expect(factor.recovery_codes.count).to eq(10)
    expect(AuditEntry.where(action: Audit::Actions::SECOND_FACTOR_ENROLLED, actor_id: @operator.id).count).to eq(1)
  end
end
