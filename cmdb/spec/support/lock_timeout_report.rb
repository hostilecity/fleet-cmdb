# #296: when a statement in the suite gives up on a lock (lock_timeout), who held locks in this test database at that
# moment, from a separate session (the timed-out one is in an aborted transaction): each holder's pid, backend type
# (an autovacuum worker shows as one), lock, relation, and query. One file per process, tmp/rspec/lock-timeouts-N.log,
# which Server CI keeps in its artifact, so the next flake of this kind is observed rather than inferred. Specs that
# provoke a lock timeout on purpose are recorded too; the file is only read when one did not.
module LockTimeoutReport
  HOLDERS = <<~SQL.squish.freeze
    SELECT l.pid, a.backend_type, a.state, l.locktype, l.mode, l.relation::regclass::text AS relation, a.xact_start,
           left(a.query, 300) AS query
      FROM pg_catalog.pg_locks l LEFT JOIN pg_catalog.pg_stat_activity a ON a.pid = l.pid
     WHERE l.granted AND l.pid IS DISTINCT FROM pg_catalog.pg_backend_pid() AND l.pid IS DISTINCT FROM $1
       AND (l.database = (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database())
            OR (l.database IS NULL AND a.datname = pg_catalog.current_database()))
     ORDER BY l.pid, l.locktype, relation
  SQL

  class << self
    attr_writer :path

    def path = @path ||= File.expand_path("../../tmp/rspec/lock-timeouts-#{(ENV['TEST_ENV_NUMBER'].to_s.empty? ? '1' : ENV['TEST_ENV_NUMBER'])}.log", __dir__)

    # config: the timed-out connection's configuration; pid: its backend, left out of the list.
    def record(config, pid, sql)
      rows = holders(config, pid)
      lines = [ "#{Time.now.utc.iso8601(3)} #{RSpec.current_example&.location || 'outside an example'} (pid #{pid}): #{sql.to_s.squish.first(300)}" ]
      lines += rows.empty? ? [ "  no other session holds a lock in this database now" ] : rows.map { |row| "  #{row.values.join(' | ')}" }
      write(lines)
    rescue StandardError => e
      write([ "#{Time.now.utc.iso8601(3)} could not list the lock holders: #{e.class}: #{e.message}" ])
    end

    private

    def holders(config, pid)
      session = PG.connect({ host: config[:host], port: config[:port], user: config[:username], password: config[:password],
                             dbname: config[:database] }.compact)
      session.exec_params(HOLDERS, [ pid ]).to_a
    ensure
      session&.close
    end

    def write(lines)
      FileUtils.mkdir_p(File.dirname(path))
      File.open(path, "a") { |file| file.puts(lines) }
    end
  end

  # Prepended to the PostgreSQL adapter: Active Record turns PostgreSQL's lock_not_available into LockWaitTimeout here.
  module Adapter
    private

    def translate_exception(exception, message:, sql:, binds:)
      error = super
      LockTimeoutReport.record(@config, timed_out_pid, sql.presence || message) if error.is_a?(ActiveRecord::LockWaitTimeout)
      error
    end

    def timed_out_pid
      @raw_connection&.backend_pid
    rescue PG::Error
      nil
    end
  end
end

FileUtils.rm_f(LockTimeoutReport.path) # this process's records only
ActiveRecord::ConnectionAdapters::PostgreSQLAdapter.prepend(LockTimeoutReport::Adapter)
