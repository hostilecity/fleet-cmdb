# A lock_timeout for one block only (#296). The block runs in a transaction of its own, or in a savepoint when the
# connection is already in one, with SET LOCAL lock_timeout. PostgreSQL keeps a SET LOCAL made in a savepoint after
# the savepoint is released, to the end of the whole transaction, so without the reset here everything after the block
# in the caller's transaction waited at most that long for any lock too: the rest of a migration after
# VulnerabilityTriage::Checks, and in a spec the rest of the example. A spec that then needed a lock autovacuum held
# gave up before PostgreSQL cancels autovacuum for a waiter (deadlock_timeout, 1 s): host_spec's TRUNCATE hosts
# CASCADE failed on CI exactly 500 ms after it started, LiveRefresh's timeout from the host the example created.
# Outside a transaction, as LiveRefresh and partition maintenance run in production, nothing is added.
module ScopedLockTimeout
  module_function

  # timeout: a PostgreSQL interval, such as "500ms". Returns the block's value; a LockWaitTimeout raised in the block
  # rolls the savepoint back, and the setting with it.
  def within(connection, timeout)
    outer = connection.select_value("SELECT pg_catalog.current_setting('lock_timeout')") if connection.transaction_open?
    result = connection.transaction(requires_new: true) do
      connection.execute("SET LOCAL lock_timeout = #{connection.quote(timeout)}")
      yield connection
    end
    connection.execute("SELECT pg_catalog.set_config('lock_timeout', #{connection.quote(outer)}, true)") if outer
    result
  end
end
