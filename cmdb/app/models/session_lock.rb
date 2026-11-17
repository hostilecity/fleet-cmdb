# Session-level advisory locks that span several transactions (#198): the liveness evaluation's (Liveness.evaluate!,
# #186) and a rollout stage prepare's (Rollouts, review of #215). The app's other advisory locks are transaction-level
# (pg_advisory_xact_lock) and end with their transaction, so they are safe behind a transaction-mode pooler.
#
# The lock is taken on DirectRecord's connection when DIRECT_DATABASE_URL is set, so it holds one server connection
# from lock to unlock whatever pools the work in the block; otherwise on the primary's connection, the one the block's
# work uses, as before. The lock is only a mutex between runs: the block's work needs nothing from its connection.
module SessionLock
  # The lock's connection was lost (and perhaps silently reopened by Active Record), which released the lock.
  class Lost < StandardError; end

  module_function

  # Runs the block holding the advisory lock named by key_sql (one bigint, or two ints, as SQL), and returns its value;
  # returns nil without running it when another session holds the lock. The block is given a check that raises Lost if
  # the lock's server session has ended, which released the lock (Active Record reopens a lost connection without a
  # word, so the check compares the server process): a run calls it between batches, so it never goes on unlocked. The lock is released first in ensure; if that fails, the connection is
  # closed and dropped from the pool, which releases it (review of #212).
  def hold(key_sql)
    pool.with_connection do |connection|
      pid, locked = connection.select_rows("SELECT pg_backend_pid(), pg_try_advisory_lock(#{key_sql})").first
      return nil unless locked

      begin
        yield -> { connection.select_value("SELECT pg_backend_pid()") == pid or raise Lost, "the session holding advisory lock #{key_sql} ended" }
      ensure
        release(connection, key_sql)
      end
    end
  end

  # DirectRecord's pool when the direct database is configured, else the primary's.
  def pool = DirectRecord.configured? ? DirectRecord.connection_pool : ApplicationRecord.connection_pool

  def release(connection, key_sql)
    connection.select_value("SELECT pg_advisory_unlock(#{key_sql})")
  rescue ActiveRecord::ActiveRecordError
    connection.throw_away!
  end
  private_class_method :release
end
