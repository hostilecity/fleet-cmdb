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
  # Another backfill holds the lock (two `docker exec` at once, for example): nothing was done by this one.
  class Busy < StandardError; end

  # Seconds per unit of work, what estimated_seconds adds up (reviews of #240 and #250; the calibration is in
  # docs/operations/upgrades.md). Each distinct list costs SECONDS_PER_LIST, and each package in it SECONDS_PER_PACKAGE
  # to read, bucket and hash; each package of a chunk that is not stored yet costs SECONDS_PER_NEW_PACKAGE to insert (a
  # fleet whose lists share most chunks pays little of it; large, varied lists pay it for every package); each dpkg row
  # pointed at a set costs SECONDS_PER_ROW, and each finding copied SECONDS_PER_FINDING. On a quiet 2-CPU machine they
  # measured about 9.5 ms, 5 us, 53 us, 21 us and 18 us; these are about three times that, and cover the runs on the
  # same machine under a load average of 9 to 11 (500 lists of 3,000 new packages took 302 s; 400,000 rows 38 s).
  SECONDS_PER_LIST = 0.03
  SECONDS_PER_PACKAGE = 0.00002
  SECONDS_PER_NEW_PACKAGE = 0.00018
  SECONDS_PER_ROW = 0.0001
  SECONDS_PER_FINDING = 0.00012
  # How long the count of new chunk packages may take. Past it the estimate counts every package as new (the bound).
  NEW_PACKAGES_TIMEOUT = "30s".freeze
  # The session advisory lock that keeps two backfills from running at once, through SessionLock (#198): on the direct
  # connection behind a transaction-mode pooler, uncached, and checked before each batch. LOCK takes it in a statement
  # of its own (the specs hold it from another session).
  LOCK_KEY = "196, 3".freeze
  LOCK = "SELECT pg_try_advisory_lock(#{LOCK_KEY})".freeze

  BATCH = 1_000
  FINDINGS_BATCH = 10_000
  # What estimate returns: its sum in seconds, and the counts it took (in its order, up to where it stopped).
  Estimate = Data.define(:seconds, :counts)
  Package = AgentApi::PackageReport::Package
  UNSET = { manager: "dpkg", package_set_id: nil }.freeze
  INDEXES = [
    "CREATE INDEX IF NOT EXISTS package_snapshots_backfill_196 ON package_snapshots (content_hash) WHERE manager = 'dpkg' AND package_set_id IS NULL",
    "CREATE INDEX IF NOT EXISTS host_package_sets_backfill_196 ON host_package_sets (content_hash) WHERE manager = 'dpkg' AND package_set_id IS NULL"
  ].freeze

  def initialize(log: ->(_message) { })
    @log = log
    @connection = ApplicationRecord.connection
    @still_held = SessionLock::UNCHECKED
  end

  # Whether the old storage is still there to move.
  def needed? = @connection.table_exists?(:host_packages)

  # How much is left: distinct dpkg hashes (hosts and snapshots), unreadable hosts, the dpkg rows to point at a set, and
  # finding rows not copied. Each count reads its whole table (packages:backfill prints them).
  def pending
    return { "hashes" => 0, "unreadable_hosts" => 0, "rows" => 0, "findings" => 0 } unless needed?

    { "hashes" => [ HostPackageSet, PackageSnapshot ].sum { |model| model.where(UNSET).distinct.count(:content_hash) },
      "unreadable_hosts" => unreadable.count,
      "rows" => [ HostPackageSet, PackageSnapshot ].sum { |model| model.where(UNSET).count },
      "findings" => VulnerabilityFinding.where(last_ecosystem: nil).count }
  end

  # How long the work left should take, in seconds, and what it counted, from the rates above. With within: (the
  # migration's limit) it stops once the sum is past it, and each count stops at what could still fit, so the estimate
  # reads a bounded part of a large database rather than all of it; the sum it returns is then only a lower bound.
  # Counted in this order: rows, findings, lists, the lists' packages, and of those the packages of new chunks.
  def estimate(within: nil)
    counts = {}
    seconds = 0.0
    left = ->(rate) { within && ((within - seconds) / rate).floor + 1 }
    add = lambda do |what, rate, count|
      counts[what] = count
      seconds += count * rate
      within && seconds > within
    end
    return Estimate.new(seconds:, counts:) unless needed?

    rows = [ HostPackageSet, PackageSnapshot ].sum { |model| capped(model.where(UNSET), left.call(SECONDS_PER_ROW)) }
    return Estimate.new(seconds:, counts:) if add.call("rows", SECONDS_PER_ROW, rows)
    return Estimate.new(seconds:, counts:) if add.call("findings", SECONDS_PER_FINDING, capped(VulnerabilityFinding.where(last_ecosystem: nil), left.call(SECONDS_PER_FINDING)))

    # Rows are within the limit here, so these read at most that many rows.
    lists = [ HostPackageSet, PackageSnapshot ].sum { |model| model.where(UNSET).distinct.count(:content_hash) } + unreadable.count
    return Estimate.new(seconds:, counts:) if add.call("lists", SECONDS_PER_LIST, lists)

    packages = [ HostPackageSet, PackageSnapshot ].sum { |model| distinct_packages(model) } + unreadable.sum(:package_count)
    return Estimate.new(seconds:, counts:) if add.call("packages", SECONDS_PER_PACKAGE, packages)

    # Every package new is the bound: count the new chunks only when the bound would not fit.
    fits = !within || seconds + packages * SECONDS_PER_NEW_PACKAGE <= within
    add.call("new_packages", SECONDS_PER_NEW_PACKAGE, fits ? packages : new_chunk_packages || packages)
    Estimate.new(seconds:, counts:)
  end

  # The estimate's seconds alone.
  def estimated_seconds(within: nil) = estimate(within:).seconds

  # Runs the backfill under a session advisory lock, so a second one at once refuses (Busy) instead of racing it. A run
  # whose lock was lost part-way stops before its next batch (SessionLock::Lost); run it again to carry on.
  def run!
    return @log.call("nothing to move: host_packages is gone") unless needed?

    ran = SessionLock.hold(LOCK_KEY) do |still_held|
      @still_held = still_held
      backfill
      true
    ensure
      @still_held = SessionLock::UNCHECKED
    end
    raise Busy, "another package backfill is running; wait for it to finish (docs/operations/upgrades.md)" unless ran
  end

  private

  # The packages of the distinct lists of model's dpkg rows with no set yet (one list per content hash).
  def distinct_packages(model)
    model.from(model.where(UNSET).select("DISTINCT ON (content_hash) package_count").order(:content_hash), model.table_name).sum(:package_count)
  end

  def unreadable = HostPackageSet.where(manager: "unreadable", package_set_id: nil)

  # How many rows scope has, counting at most cap of them (all with no cap).
  def capped(scope, cap) = cap ? scope.limit(cap).count : scope.count

  # The packages of the chunks the backfill would store (ADR 0028: a chunk is a list's packages whose source package
  # falls in one bucket, as PackageStore.bucket computes it), each distinct chunk counted once, from one row per
  # distinct list (a list stored as a JSON string is read as the backfill reads it); a chunk already stored counts too. Nil when it takes longer than NEW_PACKAGES_TIMEOUT.
  def new_chunk_packages
    ApplicationRecord.transaction(requires_new: true) do
      before = @connection.select_value("SHOW statement_timeout")
      @connection.execute("SET LOCAL statement_timeout = '#{NEW_PACKAGES_TIMEOUT}'")
      @connection.select_value(NEW_CHUNK_PACKAGES).to_i.tap { @connection.execute(ApplicationRecord.sanitize_sql_array([ "SET LOCAL statement_timeout = ?", before ])) }
    end
  rescue ActiveRecord::QueryCanceled
    nil
  end

  NEW_CHUNK_PACKAGES = <<~SQL.squish.freeze
    WITH packages AS (
      SELECT 's' || s.content_hash AS list, e ->> 0 AS name, e ->> 1 AS architecture, e ->> 2 AS version, e ->> 3 AS source
      FROM (SELECT DISTINCT ON (content_hash) content_hash, packages FROM package_snapshots
            WHERE manager = 'dpkg' AND package_set_id IS NULL ORDER BY content_hash) s,
           jsonb_array_elements(CASE jsonb_typeof(s.packages::jsonb) WHEN 'string' THEN (s.packages::jsonb #>> '{}')::jsonb ELSE s.packages::jsonb END) e
      UNION ALL
      SELECT 'h' || h.content_hash, p.name, p.architecture, p.version, p.source
      FROM (SELECT DISTINCT ON (content_hash) content_hash, host_id FROM host_package_sets
            WHERE manager = 'dpkg' AND package_set_id IS NULL ORDER BY content_hash) h
      JOIN host_packages p ON p.host_id = h.host_id
      UNION ALL
      SELECT 'u' || u.host_id, p.name, p.architecture, p.version, p.source
      FROM host_package_sets u JOIN host_packages p ON p.host_id = u.host_id
      WHERE u.manager = 'unreadable' AND u.package_set_id IS NULL
    ), chunks AS (
      SELECT get_byte(sha256(convert_to(COALESCE(source, name), 'UTF8')), 1) % #{PackageStore::BUCKETS} AS bucket,
             md5(string_agg(concat_ws(chr(31), name, architecture, version, COALESCE(source, '')), chr(30)
                            ORDER BY name, architecture, version, source)) AS content, count(*) AS size
      FROM packages GROUP BY list, 1
    )
    SELECT COALESCE(sum(size), 0) FROM (SELECT DISTINCT ON (bucket, content) size FROM chunks) distinct_chunks
  SQL

  def backfill
    # The temporary indexes only when there are lists to store: a re-run after the step builds none (each scans the table).
    if [ HostPackageSet, PackageSnapshot ].any? { |model| model.where(UNSET).exists? } || unreadable.exists?
      INDEXES.each { |sql| @connection.execute(sql) }
      @connection.execute("ANALYZE package_snapshots, host_package_sets")
    end
    hosts
    unreadable_hosts
    snapshots
    findings
    evaluations
    @connection.execute("DROP INDEX IF EXISTS package_snapshots_backfill_196")
    @connection.execute("DROP INDEX IF EXISTS host_package_sets_backfill_196")
  end

  def hosts
    by_hash(HostPackageSet, "hosts") do |scope|
      PackageStore.store!(host_rows(scope.pick(:host_id)))
    end
  end

  def unreadable_hosts
    after = 0
    loop do
      ids = HostPackageSet.where(manager: "unreadable", package_set_id: nil).where(host_id: (after + 1)..)
                          .where("EXISTS (SELECT 1 FROM host_packages p WHERE p.host_id = host_package_sets.host_id)").order(:host_id).limit(BATCH).pluck(:host_id)
      break if ids.empty?

      @still_held.call
      ApplicationRecord.transaction { ids.each { |id| HostPackageSet.where(host_id: id).update_all(package_set_id: PackageStore.store!(host_rows(id))) } }
      after = ids.last
    end
  end

  def snapshots
    by_hash(PackageSnapshot, "snapshots") do |scope|
      list = scope.pick(:packages)
      PackageStore.store!((list.is_a?(String) ? JSON.parse(list) : list).map { |row| Package.from_a(row) }) # cast or not, as the schema cache knows it
    end
  end

  # For each distinct dpkg content hash of model's table with no set yet, by keyset on the temporary index, BATCH a
  # transaction: yields the scope of its rows, and points them all at the set id the block returns.
  def by_hash(model, label)
    after = ""
    done = 0
    loop do
      hashes = model.where(UNSET).where("content_hash > ?", after).distinct.order(:content_hash).limit(BATCH).pluck(:content_hash)
      break if hashes.empty?

      @still_held.call
      ApplicationRecord.transaction do
        hashes.each do |hash|
          scope = model.where(UNSET).where(content_hash: hash)
          scope.update_all(package_set_id: yield(scope))
        end
      end
      done += hashes.size
      after = hashes.last
      @log.call("#{label}: #{done} distinct package lists stored")
    end
  end

  # By keyset over the ids of the rows left (not over id ranges), so the time follows the rows, however sparse the ids
  # are after retention deleted resolved findings (review of #250).
  def findings
    keyset(VulnerabilityFinding.where(last_ecosystem: nil), :id) do |ids|
      VulnerabilityFinding.where(id: ids)
                          .update_all("last_source = source, last_installed_version = installed_version, last_fixed_version = fixed_version, last_ecosystem = ecosystem")
    end
    @log.call("findings: details copied")
  end

  def evaluations
    keyset(HostVulnerabilityEvaluation.where(package_set_id: nil), :host_id) do |ids|
      HostVulnerabilityEvaluation.where(host_id: ids)
                                 .update_all("package_set_id = (SELECT h.package_set_id FROM host_package_sets h WHERE h.host_id = host_vulnerability_evaluations.host_id)")
    end
  end

  # Yields the keys of scope's rows in batches of FINDINGS_BATCH, in key order, each after the last one yielded.
  def keyset(scope, key)
    after = 0
    loop do
      ids = scope.where(key => (after + 1)..).order(key).limit(FINDINGS_BATCH).pluck(key)
      break if ids.empty?

      @still_held.call
      yield ids
      after = ids.last
    end
  end

  def host_rows(host_id)
    sql = ApplicationRecord.sanitize_sql_array([ "SELECT name, architecture, version, source FROM host_packages WHERE host_id = ?", host_id ])
    @connection.select_rows(sql).map { |row| Package.from_a(row) }
  end
end
