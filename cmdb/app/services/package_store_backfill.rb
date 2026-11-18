# Moves a database upgraded from before #196 into the package store (ADR 0028, "Migration from the current schema"):
# run by the migration BackfillPackageSets when the work is small, or by `bin/rails packages:backfill` before it when
# it is not (docs/operations/upgrades.md). Idempotent and resumable: each step reads only rows that have no set or no
# copied details yet, in keyset batches of BATCH, each its own short transaction, so it can be stopped and run again.
#
# - Hosts: only dpkg hosts are grouped. Hosts with the same host_package_sets.content_hash and a dpkg manager have the
#   same list, so the set is stored once per hash from one host's host_packages rows, and every such host points at it.
# - An unreadable host's set is built from its own host_packages rows: its content_hash hashes only the manager and
#   reason (AgentApi::PackageReport#content_hash), while PackageRecorder kept its previous rows, so unreadable hosts
#   with one reason share a hash but not a list. One that was never readable (no rows) gets no set. An unsupported
#   host gets no set.
# - Snapshots: every dpkg snapshot gets the set of its JSON list, once per content hash (the snapshot hash covers the
#   list, so one hash is one list). That includes each host's newest snapshot, which retention keeps however old.
# - Findings: last_source, last_installed_version, last_fixed_version, and last_ecosystem take the finding's current
#   details, and each host's evaluation names its set (HostVulnerabilityEvaluation#package_set_id).
#
# Linear in the rows: temporary partial indexes on content_hash WHERE package_set_id IS NULL serve every lookup and
# shrink as rows are done (they are dropped at the end), and each batch of distinct hashes is read by keyset from them.
# It uses PackageStore, so the sets it stores hash exactly as a package report's would.
class PackageStoreBackfill
  BATCH = 1_000
  FINDINGS_BATCH = 10_000
  Package = AgentApi::PackageReport::Package
  INDEXES = { "package_snapshots" => "package_snapshots_backfill_196", "host_package_sets" => "host_package_sets_backfill_196" }.freeze

  def initialize(log: ->(_message) { })
    @log = log
    @connection = ApplicationRecord.connection
  end

  # Whether the old storage is still there to move.
  def needed? = @connection.table_exists?(:host_packages)

  # How much is left: distinct dpkg hashes (hosts and snapshots), unreadable hosts, and finding rows not copied.
  def pending
    return { "hashes" => 0, "unreadable_hosts" => 0, "findings" => 0 } unless needed?

    { "hashes" => value("SELECT count(DISTINCT content_hash) FROM host_package_sets WHERE manager = 'dpkg' AND package_set_id IS NULL") +
                  value("SELECT count(DISTINCT content_hash) FROM package_snapshots WHERE manager = 'dpkg' AND package_set_id IS NULL"),
      "unreadable_hosts" => value("SELECT count(*) FROM host_package_sets WHERE manager = 'unreadable' AND package_set_id IS NULL"),
      "findings" => value("SELECT count(*) FROM vulnerability_findings WHERE last_ecosystem IS NULL") }
  end

  def run!
    return @log.call("nothing to move: host_packages is gone") unless needed?

    create_indexes
    hosts
    unreadable_hosts
    snapshots
    findings
    evaluations
    drop_indexes
  end

  private

  def value(sql) = @connection.select_value(sql).to_i

  def create_indexes
    INDEXES.each do |table, index|
      @connection.execute("CREATE INDEX IF NOT EXISTS #{index} ON #{table} (content_hash) WHERE manager = 'dpkg' AND package_set_id IS NULL")
    end
    @connection.execute("ANALYZE package_snapshots, host_package_sets")
  end

  def drop_indexes = INDEXES.each_value { |index| @connection.execute("DROP INDEX IF EXISTS #{index}") }

  def hosts
    by_hash("host_package_sets", "hosts") do |hash|
      host_id = @connection.select_value("SELECT host_id FROM host_package_sets WHERE manager = 'dpkg' AND package_set_id IS NULL AND content_hash = #{@connection.quote(hash)} LIMIT 1")
      set_id = PackageStore.store!(host_rows(host_id))
      @connection.execute("UPDATE host_package_sets SET package_set_id = #{set_id} WHERE manager = 'dpkg' AND package_set_id IS NULL AND content_hash = #{@connection.quote(hash)}")
    end
  end

  def unreadable_hosts
    after = 0
    loop do
      ids = @connection.select_values(<<~SQL.squish)
        SELECT host_id FROM host_package_sets WHERE manager = 'unreadable' AND package_set_id IS NULL AND host_id > #{after}
          AND EXISTS (SELECT 1 FROM host_packages p WHERE p.host_id = host_package_sets.host_id) ORDER BY host_id LIMIT #{BATCH}
      SQL
      break if ids.empty?

      @connection.transaction { ids.each { |id| @connection.execute("UPDATE host_package_sets SET package_set_id = #{PackageStore.store!(host_rows(id))} WHERE host_id = #{Integer(id)}") } }
      after = ids.last
    end
  end

  def snapshots
    by_hash("package_snapshots", "snapshots") do |hash|
      json = @connection.select_value("SELECT packages FROM package_snapshots WHERE manager = 'dpkg' AND package_set_id IS NULL AND content_hash = #{@connection.quote(hash)} LIMIT 1")
      set_id = PackageStore.store!(JSON.parse(json).map { |row| Package.from_a(row) })
      @connection.execute("UPDATE package_snapshots SET package_set_id = #{set_id} WHERE manager = 'dpkg' AND package_set_id IS NULL AND content_hash = #{@connection.quote(hash)}")
    end
  end

  # Yields each distinct dpkg content hash of table with no set yet, by keyset on the temporary index, BATCH a transaction.
  def by_hash(table, label)
    after = ""
    done = 0
    loop do
      hashes = @connection.select_values(<<~SQL.squish)
        SELECT DISTINCT content_hash FROM #{table} WHERE manager = 'dpkg' AND package_set_id IS NULL AND content_hash > #{@connection.quote(after)}
        ORDER BY content_hash LIMIT #{BATCH}
      SQL
      break if hashes.empty?

      @connection.transaction { hashes.each { |hash| yield hash } }
      done += hashes.size
      after = hashes.last
      @log.call("#{label}: #{done} distinct package lists stored")
    end
  end

  def findings
    last = value("SELECT COALESCE(max(id), 0) FROM vulnerability_findings")
    (0..last).step(FINDINGS_BATCH) do |from|
      @connection.execute(<<~SQL.squish)
        UPDATE vulnerability_findings SET last_source = source, last_installed_version = installed_version, last_fixed_version = fixed_version,
               last_ecosystem = ecosystem
        WHERE id > #{from} AND id <= #{from + FINDINGS_BATCH} AND last_ecosystem IS NULL
      SQL
    end
    @log.call("findings: details copied")
  end

  def evaluations
    last = value("SELECT COALESCE(max(host_id), 0) FROM host_vulnerability_evaluations")
    (0..last).step(FINDINGS_BATCH) do |from|
      @connection.execute(<<~SQL.squish)
        UPDATE host_vulnerability_evaluations e SET package_set_id = h.package_set_id
        FROM host_package_sets h WHERE h.host_id = e.host_id AND e.package_set_id IS NULL AND h.package_set_id IS NOT NULL
          AND e.host_id > #{from} AND e.host_id <= #{from + FINDINGS_BATCH}
      SQL
    end
  end

  def host_rows(host_id)
    @connection.select_rows("SELECT name, architecture, version, source FROM host_packages WHERE host_id = #{Integer(host_id)}").map { |row| Package.from_a(row) }
  end
end
