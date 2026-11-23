require "rails_helper"

# #296: a short lock_timeout for one block must not outlive it in the caller's transaction (here, the example's own).
RSpec.describe ScopedLockTimeout do
  let(:c) { ApplicationRecord.connection }

  def lock_timeout = c.select_value("SHOW lock_timeout")

  it "sets the timeout for the block only, and gives the caller's transaction its own value back" do
    c.execute("SET LOCAL lock_timeout = '7s'")
    inside = described_class.within(c, "150ms") { |connection| connection.select_value("SHOW lock_timeout") }
    expect(inside).to eq("150ms")
    expect(lock_timeout).to eq("7s")
  end

  it "leaves no timeout behind where the caller had none, as after a host change's live refresh (host_spec, #296)" do
    expect(lock_timeout).to eq("0")
    create(:host, :retired) # FleetBroadcast -> LiveRefresh.request, 500 ms for its own statements
    expect(lock_timeout).to eq("0")
  end

  it "returns the block's value, and drops the setting with the savepoint when the block raises" do
    expect(described_class.within(c, "1s") { 42 }).to eq(42)
    expect { described_class.within(c, "1s") { raise ActiveRecord::LockWaitTimeout, "busy" } }.to raise_error(ActiveRecord::LockWaitTimeout)
    expect(lock_timeout).to eq("0")
  end

  context "outside a transaction, as in production" do
    self.use_transactional_tests = false

    it "is a transaction of its own and sends nothing more" do
      statements = []
      callback = ->(*, payload) { statements << payload[:sql] }
      value = ActiveSupport::Notifications.subscribed(callback, "sql.active_record") do
        described_class.within(c, "200ms") { |connection| connection.select_value("SHOW lock_timeout") }
      end
      expect(value).to eq("200ms")
      expect(statements).to eq([ "BEGIN", "SET LOCAL lock_timeout = '200ms'", "SHOW lock_timeout", "COMMIT" ])
      expect(lock_timeout).to eq("0")
    end
  end
end
