require "rails_helper"

# A code is accepted once (P3-S09, Q30, threat model H5), even when two requests bring it at the same moment: the
# check locks the operator's factor row. Runs outside the test transaction so each thread commits on its own connection.
RSpec.describe SecondFactors::StepUp do
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

  it "lets only one of four requests with the same code through" do
    @operator = create(:operator)
    secret, = enrol_second_factor(@operator)
    sessions = Array.new(4) { OperatorSession.start!(@operator).first }
    code = totp_code(secret)
    gate = Concurrent::CountDownLatch.new(1)
    threads = sessions.map do |session|
      Thread.new do
        gate.wait
        ActiveRecord::Base.connection_pool.with_connection do
          SecondFactors.step_up(operator_session: session, code:, purpose: "create_task").status
        end
      rescue StandardError => e
        e
      end
    end
    gate.count_down

    expect(threads.map(&:value).tally).to eq(passed: 1, reused: 3)
    expect(SecondFactor.find_by(operator: @operator).failed_attempts).to eq(3)
  end
end
