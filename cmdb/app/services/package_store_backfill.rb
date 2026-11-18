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

  # Measured seconds per unit of work, on 2 shared CPUs (review of #240): what estimated_seconds adds up.
  SECONDS_PER_LIST = 0.03
  SECONDS_PER_FINDING = 0.00012
  # The session advisory lock that keeps two backfills from running at once, through SessionLock (#198): on the direct
  # connection behind a transaction-mode pooler, uncached, and checked before each batch. LOCK takes it in a statement
  # of its own (the specs hold it from another session).
  LOCK_KEY = "196, 3".freeze
  LOCK = "SELECT pg_try_advisory_lock(#{LOCK_KEY})".freeze

  BATCH = 1_000
  FINDINGS_BATCH = 10_000
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

  # How much is left: distinct dpkg hashes (hosts and snapshots), unreadable hosts, and finding rows not copied.
  def pending
    return { "hashes" => 0, "unreadable_hosts" => 0, "findings" => 0 } unless needed?

    { "hashes" => HostPackageSet.where(UNSET).distinct.count(:content_hash) + PackageSnapshot.where(UNSET).distinct.count(:content_hash),
      "unreadable_hosts" => HostPackageSet.where(manager: "unreadable", package_set_id: nil).count,
      "findings" => VulnerabilityFinding.where(last_ecosystem: nil).count }
  end

  # How long the work left should take, in seconds, from the measured rates.
  def estimated_seconds
    left = pending
    (left["hashes"] + left["unreadable_hosts"]) * SECONDS_PER_LIST + left["findings"] * SECONDS_PER_FINDING
  end

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

  def backfill
    INDEXES.each { |sql| @connection.execute(sql) }
    @connection.execute("ANALYZE package_snapshots, host_package_sets")
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

  def findings
    last = VulnerabilityFinding.maximum(:id).to_i
    (0..last).step(FINDINGS_BATCH) do |from|
      @still_held.call
      VulnerabilityFinding.where(id: (from + 1)..(from + FINDINGS_BATCH), last_ecosystem: nil)
                          .update_all("last_source = source, last_installed_version = installed_version, last_fixed_version = fixed_version, last_ecosystem = ecosystem")
    end
    @log.call("findings: details copied")
  end

  def evaluations
    last = HostVulnerabilityEvaluation.maximum(:host_id).to_i
    (0..last).step(FINDINGS_BATCH) do |from|
      @still_held.call
      HostVulnerabilityEvaluation.where(host_id: (from + 1)..(from + FINDINGS_BATCH), package_set_id: nil)
                                 .update_all("package_set_id = (SELECT h.package_set_id FROM host_package_sets h WHERE h.host_id = host_vulnerability_evaluations.host_id)")
    end
  end

  def host_rows(host_id)
    sql = ApplicationRecord.sanitize_sql_array([ "SELECT name, architecture, version, source FROM host_packages WHERE host_id = ?", host_id ])
    @connection.select_rows(sql).map { |row| Package.from_a(row) }
  end
end
