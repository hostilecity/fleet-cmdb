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

  # The check for work run outside any lock (a spec, or the console): it checks nothing.
  UNCHECKED = -> { }

  module_function

  # Runs the block holding the advisory lock named by key_sql (one bigint, or two ints, as SQL), and returns its value;
  # returns nil without running it when another session holds the lock. The lock is released first in ensure; if that
  # fails, the connection is closed and dropped from the pool, which releases it (review of #212).
  #
  # The block is given a check to call before each write that depends on the lock. It raises Lost when the lock's
  # server session has ended, which released the lock: Active Record reopens a lost connection without a word (on the
  # direct connection, which sits idle while the work runs elsewhere, and on the primary's own, at the next
  # transaction), so the check compares the server process id; an error on the lock's connection counts as lost too.
  # The check runs on every path, the homelab's included (the owner's decision, 2026-11-18): one small statement a
  # batch.
  #
  # Every statement here runs uncached (re-review of #237). Inside a request or a job the executor turns on the query
  # cache for every pool, so a repeated check would be answered from it with the first process id, a second hold of
  # the same key in one request would be told it got the lock without taking it, and a second unlock would not run.
  def hold(key_sql)
    pool.with_connection do |connection|
      locked, pid = connection.uncached { connection.select_rows("SELECT pg_try_advisory_lock(#{key_sql}), pg_backend_pid()").first }
      return nil unless locked

      begin
        yield -> { verify!(connection, pid, key_sql) }
      ensure
        release(connection, key_sql)
      end
    end
  end

  def direct? = DirectRecord.configured?

  # DirectRecord's pool when the direct database is configured, else the primary's.
  def pool = direct? ? DirectRecord.connection_pool : ApplicationRecord.connection_pool

  def verify!(connection, pid, key_sql)
    return if connection.uncached { connection.select_value("SELECT pg_backend_pid()") } == pid

    raise Lost, "the session holding advisory lock #{key_sql} ended"
  rescue ActiveRecord::ActiveRecordError => e
    raise Lost, "the session holding advisory lock #{key_sql} failed: #{e.class}"
  end
  private_class_method :verify!

  def release(connection, key_sql)
    connection.uncached { connection.select_value("SELECT pg_advisory_unlock(#{key_sql})") }
  rescue ActiveRecord::ActiveRecordError
    connection.throw_away!
  end
  private_class_method :release
end
