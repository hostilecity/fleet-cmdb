# The direct database (DIRECT_DATABASE_URL, #198) in a spec: DirectRecord connected to the test database on a pool of
# its own, as behind a transaction-mode pooler, where SessionLock takes its locks on it.
module DirectDatabaseHelpers
  # From a before hook; RSpec.configure below removes the connection after each example.
  def use_direct_database
    allow(DirectRecord).to receive(:configured?).and_return(true)
    DirectRecord.establish_connection(ApplicationRecord.connection_db_config.configuration_hash)
    @direct_database = true
  end

  # A session of its own: the test pins one connection per pool, which would take a lock again (it is re-entrant).
  def separate_session = ActiveRecord::ConnectionAdapters::PostgreSQLAdapter.new(ApplicationRecord.connection_db_config.configuration_hash)

  # Ends the server session that holds the advisory lock with these two keys (classid, objid) in this test database
  # only, as a dropped connection would; the lock goes with it. Returns how many sessions it ended.
  def end_lock_holder(classid, objid)
    session = separate_session
    session.select_value(<<~SQL.squish)
      SELECT count(pg_terminate_backend(l.pid)) FROM pg_locks l JOIN pg_database d ON d.oid = l.database
       WHERE l.locktype = 'advisory' AND l.granted AND d.datname = current_database() AND l.classid = #{Integer(classid)} AND l.objid = #{Integer(objid)}
    SQL
  ensure
    session&.disconnect!
  end
end

RSpec.configure do |config|
  config.include DirectDatabaseHelpers
  # Only when this example connected it: on a class with no connection of its own, remove_connection would remove
  # ActiveRecord::Base's.
  config.after { DirectRecord.remove_connection if @direct_database }
end
