require "rails_helper"

# A rules file preview (P2-D06): one per operator, even when two uploads arrive at once and the operator has no
# preview yet (review of #130). Runs outside the test transaction so each thread commits on its own connection.
RSpec.describe RuleImportPreview do
  self.use_transactional_tests = false

  let!(:operator) { create(:operator) }

  after do
    described_class.delete_all
    Operator.where(id: operator.id).delete_all
  end

  def store(name) = described_class.store!(operator:, filename: name, body: "rules: []", disable_missing: false, rules_digest: "0" * 64)

  it "serialises two first uploads by one operator: the second waits, then replaces the first" do
    stored = Concurrent::CountDownLatch.new(1)
    release = Concurrent::CountDownLatch.new(1)
    first = Thread.new do
      ActiveRecord::Base.connection_pool.with_connection do
        described_class.transaction do
          store("first.yml")
          stored.count_down
          release.wait(10) # the first upload has not committed yet
        end
      end
    end
    stored.wait(10)
    second = Thread.new { ActiveRecord::Base.connection_pool.with_connection { store("second.yml") } }
    sleep 0.2 # the second upload is waiting, not failing
    expect(second).to be_alive
    release.count_down
    first.join
    expect { second.join }.not_to raise_error
    expect(described_class.where(operator:).pluck(:filename)).to eq([ "second.yml" ])
  end
end
