require "rails_helper"

# Session-level advisory locks across transactions (#198): on the primary's own connection by default, exactly as
# before, and on the direct database's connection when DIRECT_DATABASE_URL is set, so a transaction-mode pooler in
# front of the primary cannot split a lock from its unlock.
RSpec.describe SessionLock do
  KEY = "1234567, 89".freeze

  def holders = ApplicationRecord.uncached do
    ApplicationRecord.connection.select_values(<<~SQL.squish)
      SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND classid = 1234567 AND objid = 89 AND granted
         AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
    SQL
  end

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

    it "checks the lock with one uncached statement on its own connection, and raises Lost once the session changed" do
      sql = statements do
        described_class.hold(KEY) do |still_held|
          2.times { still_held.call }
        end
      end
      expect(sql).to eq([ "SELECT pg_try_advisory_lock(#{KEY}), pg_backend_pid()", "SELECT pg_backend_pid()", "SELECT pg_backend_pid()",
                          "SELECT pg_advisory_unlock(#{KEY})" ])

      # The homelab's path too (the owner's decision, 2026-11-18): the connection was reopened at the next transaction,
      # so the server process differs and the lock is gone.
      connection = ApplicationRecord.connection
      expect do
        described_class.hold(KEY) do |still_held|
          allow(connection).to receive(:select_value).and_call_original
          allow(connection).to receive(:select_value).with("SELECT pg_backend_pid()").and_return(-1)
          still_held.call
        end
      end.to raise_error(SessionLock::Lost, /ended/)
    end

    # Inside one request or job the query cache is on: a second hold of the same key would be told it got the lock
    # without taking it, and its unlock would not run, if any of these statements were cached (final check of #237).
    it "takes and releases the same lock twice in one executor run" do
      Rails.application.executor.wrap do
        expect(ApplicationRecord.connection.query_cache_enabled).to be(true)
        2.times do
          expect(described_class.hold(KEY) { holders.size }).to eq(1)
          expect(holders).to be_empty
        end
      end
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
      expect(other.select_value("SELECT pg_try_advisory_lock(#{KEY})")).to be(true) # never blocks: a lock left held fails here
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
      # Inside the executor, as a request or job runs it: the query cache is on for the direct pool, and the check must
      # still reach the server (re-review of #237).
      expect do
        Rails.application.executor.wrap do
          described_class.hold(KEY) do |still_held|
            expect(DirectRecord.connection_pool.query_cache_enabled).to be(true)
            still_held.call
            expect(end_lock_holder(1_234_567, 89)).to eq(1)
            expect(other.select_value("SELECT pg_try_advisory_lock(#{KEY})")).to be(true) # the lock is free
            still_held.call
          end
        end
      end.to raise_error(SessionLock::Lost, /advisory lock 1234567, 89/)
    ensure
      other&.disconnect!
    end

    it "raises Lost when the lock's connection was reopened without a word" do
      expect do
        Rails.application.executor.wrap do
          described_class.hold(KEY) do |still_held|
            still_held.call
            DirectRecord.connection_pool.with_connection(&:disconnect!)
            still_held.call
          end
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
