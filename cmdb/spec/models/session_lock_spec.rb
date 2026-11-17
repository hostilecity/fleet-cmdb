require "rails_helper"

# Session-level advisory locks across transactions (#198): on the primary's own connection by default, as before, and
# on the direct database's connection when DIRECT_DATABASE_URL is set, so a transaction-mode pooler in front of the
# primary cannot split a lock from its unlock.
RSpec.describe SessionLock do
  KEY = "1234567, 89".freeze

  def holders = ApplicationRecord.connection.select_values(
    "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND classid = 1234567 AND objid = 89 AND granted"
  )

  it "takes the lock on the primary's connection by default, runs the block, and releases it" do
    expect(described_class.pool).to eq(ApplicationRecord.connection_pool)
    pid = ApplicationRecord.connection.select_value("SELECT pg_backend_pid()")
    seen = described_class.hold(KEY) do |still_held|
      still_held.call
      holders
    end
    expect(seen).to eq([ pid ])
    expect(holders).to be_empty
  end

  describe "with a direct database" do
    before do
      allow(DirectRecord).to receive(:configured?).and_return(true)
      DirectRecord.establish_connection(ApplicationRecord.connection_db_config.configuration_hash)
    end

    after { DirectRecord.remove_connection }

    it "takes the lock on the direct connection, not the one the block's work uses" do
      expect(described_class.pool).to eq(DirectRecord.connection_pool)
      work = ApplicationRecord.connection.select_value("SELECT pg_backend_pid()")
      seen = described_class.hold(KEY) { holders }
      expect(seen.size).to eq(1)
      expect(seen).not_to include(work)
      expect(holders).to be_empty
    end

    it "does not run the block while another session holds the lock" do
      # A session of its own: the test pins one connection per pool, which would take the lock again (it is re-entrant).
      other = ActiveRecord::ConnectionAdapters::PostgreSQLAdapter.new(ApplicationRecord.connection_db_config.configuration_hash)
      other.execute("SELECT pg_advisory_lock(#{KEY})")
      ran = false
      expect(described_class.hold(KEY) { ran = true }).to be_nil
      expect(ran).to be(false)
    ensure
      other&.disconnect!
    end

    it "raises from the check once the lock's connection has broken, so a run never goes on unlocked" do
      expect do
        described_class.hold(KEY) do |still_held|
          DirectRecord.connection_pool.with_connection(&:disconnect!)
          still_held.call
        end
      end.to raise_error(SessionLock::Lost, /advisory lock 1234567, 89/)
      expect(holders).to be_empty # Active Record reopened the connection, without the lock
    end
  end
end
