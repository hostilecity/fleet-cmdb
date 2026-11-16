module FleetBenchmark
  # The write-ahead log a load run made in the benchmark database (#192), read back with pg_walinspect between the LSNs
  # at the start and the end of the run. Other databases on the same server write WAL too, so pg_current_wal_lsn deltas
  # alone overstate a run's share; this counts only the records whose blocks are in this database, and the commit records
  # of the transactions that wrote them. Autovacuum and pruning of this database's tables are included: they are part of
  # what the run's writes cost. A temporary physical slot keeps the run's WAL on disk until it has been read.
  #
  # Needs a superuser (or pg_read_server_files) and the pg_walinspect extension, which it creates in the benchmark
  # database; without them it reports the cluster-wide LSN delta only.
  class WalWindow
    SLOT = "fleet_benchmark_#{Process.pid}".freeze

    # Uncached: the LSN queries are the same text at the start and the end of the run.
    def self.open(conn) = ApplicationRecord.uncached { new(conn).tap(&:start) }

    def initialize(conn)
      @conn = conn
      @inspect = false
    end

    def start
      begin
        @conn.execute("CREATE EXTENSION IF NOT EXISTS pg_walinspect")
        @conn.execute("SELECT pg_create_physical_replication_slot('#{SLOT}', true, true)")
        @inspect = true
      rescue ActiveRecord::StatementInvalid => e
        warn "[wal] pg_walinspect unavailable (#{e.message.lines.first.strip}); reporting the cluster-wide LSN delta only"
      end
      @start = @conn.select_value("SELECT pg_current_wal_insert_lsn()::text")
    end

    # The end of the run's range, taken as soon as the run ends.
    def stop = @finish ||= ApplicationRecord.uncached { @conn.select_value("SELECT pg_current_wal_insert_lsn()::text") }

    # { "wal_cluster_bytes", "wal_bytes", "wal_fpi_bytes", "wal_records", "wal_by_relation" => [[name, bytes], ...] }.
    # Its temporary table writes rows, so read the run's other counters first.
    def finish = ApplicationRecord.uncached { read(stop) }

    private

    def read(finish_lsn)
      result = { "wal_cluster_bytes" => @conn.select_value("SELECT pg_wal_lsn_diff('#{finish_lsn}', '#{@start}')").to_i }
      return result unless @inspect

      result.merge(attributed(finish_lsn))
    ensure
      @conn.execute("SELECT pg_drop_replication_slot('#{SLOT}')") if @inspect
    end

    # The range is read once into a temporary table: on a busy server it can hold hundreds of megabytes of other
    # databases' WAL.
    def attributed(finish_lsn)
      @conn.execute(<<~SQL)
        CREATE TEMPORARY TABLE fleet_benchmark_wal AS
        WITH r AS (
          SELECT xid, record_length, fpi_length,
                 substring(block_ref from 'rel [0-9]+/([0-9]+)/')::oid AS db,
                 substring(block_ref from 'rel [0-9]+/[0-9]+/([0-9]+)')::oid AS filenode
            FROM pg_get_wal_records_info('#{@start}', '#{finish_lsn}')
        ), here AS (SELECT oid FROM pg_database WHERE datname = current_database()),
        writers AS (SELECT DISTINCT xid FROM r WHERE db = (SELECT oid FROM here) AND xid <> 0)
        SELECT r.record_length, r.fpi_length, r.filenode
          FROM r
         WHERE r.db = (SELECT oid FROM here) OR (r.db IS NULL AND r.xid IN (SELECT xid FROM writers))
      SQL
      totals = @conn.select_one("SELECT count(*) AS records, COALESCE(sum(record_length), 0) AS bytes, COALESCE(sum(fpi_length), 0) AS fpi " \
                                "FROM fleet_benchmark_wal")
      by_relation = @conn.select_rows(<<~SQL)
        SELECT COALESCE(pg_filenode_relation(0, filenode)::text, CASE WHEN filenode IS NULL THEN '(commits)' ELSE '(other)' END), sum(record_length)
          FROM fleet_benchmark_wal GROUP BY 1 ORDER BY 2 DESC LIMIT 10
      SQL
      { "wal_records" => totals["records"].to_i, "wal_bytes" => totals["bytes"].to_i, "wal_fpi_bytes" => totals["fpi"].to_i,
        "wal_by_relation" => by_relation.map { |name, bytes| [ name, bytes.to_i ] } }
    ensure
      @conn.execute("DROP TABLE IF EXISTS fleet_benchmark_wal")
    end
  end
end
