require "rails_helper"

# Session-level advisory locks across transactions (#198): on the primary's own connection by default, exactly as
# before, and on the direct database's connection when DIRECT_DATABASE_URL is set, so a transaction-mode pooler in
# front of the primary cannot split a lock from its unlock.
RSpec.describe SessionLock do
  KEY = "1234567, 89".freeze

  def holders = ApplicationRecord.connection.select_values(
    "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND classid = 1234567 AND objid = 89 AND granted"
  )

  def statements(&)
    sql = []
    ActiveSupport::Notifications.subscribed(->(*, payload) { sql << payload[:sql] }, "sql.active_record", &)
    sql
  end

  describe "by default (nothing set)" do
    it "takes the lock on the primary's connection, runs the block, and releases it" do
      expect(described_class.pool).to eq(ApplicationRecord.connection_pool)
      pid = ApplicationRecord.connection.select_value("SELECT pg_backend_pid()")
      expect(described_class.hold(KEY) { holders }).to eq([ pid ])
      expect(holders).to be_empty
    end

    it "runs the statements it ran before #198, and its check runs none" do
      sql = statements do
        described_class.hold(KEY) do |still_held|
          3.times { still_held.call }
        end
      end
      expect(sql).to eq([ "SELECT pg_try_advisory_lock(#{KEY})", "SELECT pg_advisory_unlock(#{KEY})" ])
    end
  end

  describe "with a direct database" do
    before { use_direct_database }

    it "takes the lock on the direct connection, not the one the block's work uses" do
      expect(described_class.pool).to eq(DirectRecord.connection_pool)
      work = ApplicationRecord.connection.select_value("SELECT pg_backend_pid()")
      seen = described_class.hold(KEY) do |still_held|
        still_held.call
        holders
      end
      expect(seen.size).to eq(1)
      expect(seen).not_to include(work)
      expect(holders).to be_empty
    end

    it "does not run the block while another session holds the lock" do
      other = separate_session
      other.execute("SELECT pg_advisory_lock(#{KEY})")
      ran = false
      expect(described_class.hold(KEY) { ran = true }).to be_nil
      expect(ran).to be(false)
    ensure
      other&.disconnect!
    end

    # The review of #237's reproduction: the lock's session ends while the block works on another connection. Another
    # session can then take the lock while the block is still running, and the block's next check stops it.
    it "raises Lost from the check once the lock's session has ended, while another session can take the lock" do
      other = separate_session
      expect do
        described_class.hold(KEY) do |still_held|
          still_held.call
          expect(end_lock_holder(1_234_567, 89)).to eq(1)
          expect(other.select_value("SELECT pg_try_advisory_lock(#{KEY})")).to be(true) # the lock is free
          still_held.call
        end
      end.to raise_error(SessionLock::Lost, /advisory lock 1234567, 89/)
    ensure
      other&.disconnect!
    end

    it "raises Lost when the lock's connection was reopened without a word" do
      expect do
        described_class.hold(KEY) do |still_held|
          DirectRecord.connection_pool.with_connection(&:disconnect!)
          still_held.call
        end
      end.to raise_error(SessionLock::Lost, /ended/)
      expect(holders).to be_empty
    end

    it "raises Lost when the check itself fails" do
      expect do
        described_class.hold(KEY) do |still_held|
          allow(DirectRecord.connection_pool.lease_connection).to receive(:select_value).and_call_original
          allow(DirectRecord.connection_pool.lease_connection).to receive(:select_value).with("SELECT pg_backend_pid()").and_raise(ActiveRecord::ConnectionFailed)
          still_held.call
        end
      end.to raise_error(SessionLock::Lost, /failed: ActiveRecord::ConnectionFailed/)
    end
  end
end
