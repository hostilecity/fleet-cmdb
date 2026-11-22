class EvaluationRun
  # A re-triage (VT-BUCKETS #259, VT-S05, the epic's VT-M6): after an exploitation signal, an advisory's vector or
  # severity, or Debian's triage changed, the base bucket of the chunk verdicts holding the advisories concerned is
  # recomputed, then the transitions of the hosts on sets holding a chunk whose base bucket or KEV flag changed run
  # (ADR 0028's path), in the run's batches (VulnerabilityMatcher, locked in host id order and sized by lock time).
  #
  # - prepare! (once, as the run fans out) follows TriageSignalChange's claim protocol: it claims pending changes
  #   (oldest first, no lock), recomputes from the current data (VulnerabilityTriage::Base.refresh!, which commits),
  #   records the chunks that changed (triage_run_chunks), and only then releases the claimed rows, outside any
  #   transaction. A run that fails before that releases nothing. kev rows are processed with the advisory rows in one
  #   pass that reads the data after both were claimed, so an alias an advisory import added before a KEV import
  #   committed its CVE is covered by the kev row.
  # - Each host re-triages only the findings of the advisories concerned (VulnerabilityMatcher.retriage!): a signal or
  #   tracker change moves nothing else, so a KEV listing costs a host its few findings of that advisory, not its
  #   thousands. A full run, or one naming more than ADVISORY_LIMIT advisories, runs the hosts' whole transitions.
  # - Which changes: reason "kev" (a KEV import or a KEV clear; started at once) claims kev, kev_all, and advisory;
  #   "daily" (TriageDailyJob, after the daily EPSS import) claims every kind, so EPSS and tracker changes are coalesced
  #   into one run a day; "all" (the migration that adds the buckets, bin/rails vulnerabilities:triage) recomputes
  #   every verdict and every host. A kev_all change (KEV data appeared or was cleared, so rule I5 turns on or off
  #   everywhere) makes the run "all" too.
  # - Staleness starts nothing and rewrites nothing (B1): only stored data changing does.
  # - A failed run can be started again (the Data sources page, Triage.retry!): a prepared run with batches left carries
  #   on from them; any other is started again as a new run whose scope names the chunks it recorded, so it re-runs the
  #   same hosts without claiming again, and supersedes it. A later run covers an earlier one only when it
  #   re-runs every host the earlier one would (its chunks, or all), so latest-wins never drops a host.
  class Triage
    AT_ONCE = %w[kev kev_all advisory].freeze
    REASONS = %w[kev daily all].freeze
    # How many times in a row TriageRunWatchJob resumes a run whose job died with no progress since the last resume,
    # before it fails the run. A resume after progress starts the count again, so a long full run survives any number
    # of deploys.
    RESUMES = 3
    CLAIM = 1_000
    CHUNK_BATCH = 5_000
    # Up to this many advisories, the run re-triages only their findings on each host (VulnerabilityMatcher.retriage!,
    # about 1 ms a host); above it (a first tracker import names most of them), each host's transitions run in full,
    # about 80 ms a host at 4,450 findings: 21 thread-hours at a million hosts, as the migration's full run costs. The
    # advisory ids are kept in the run's scope, so the limit also bounds that row.
    ADVISORY_LIMIT = 20_000

    # Starts a failed run again (Data sources' "Re-triage again"), with a fresh resume count (fourth review of #277):
    # a prepared run with batches left is reopened and carries on from them, as a resume does, so a failed full run
    # does not start from scratch; any other is started again as a new run from its scope, which covers it.
    def self.retry!(run)
      reopened = EvaluationRun.transaction do
        locked = EvaluationRun.lock.find(run.id)
        next false unless locked.failed? && locked.work.prepared? && locked.batches.exists?

        locked.update!(state: "running", finished_at: nil, scope: locked.scope.except(*RESUME_KEYS))
        ActiveRecord.after_all_transactions_commit { EvaluationRunJob.perform_later(run.id) }
        true
      end
      reopened ? run.reload : EvaluationRun.start!("triage", run.scope.except(*RESUME_KEYS))
    end

    # What TriageRunWatchJob keeps in a run's scope: how many resumes in a row made no progress, and the progress
    # (batches done) at the last one.
    RESUME_KEYS = %w[resumes resume_progress].freeze

    # Starts a run once the current transaction commits.
    def self.start_after_commit(reason) = EvaluationRun.after_commit_start("triage", { "reason" => reason })

    def initialize(scope, run_id = nil)
      @scope = scope.to_h.stringify_keys
      @run_id = run_id
    end

    attr_reader :scope, :run_id

    def reason = scope["reason"]
    def full? = scope["full"] == true || reason == "all"
    def prepared? = scope["prepared"] == true
    def chunk_runs = Array(scope["chunk_runs"]).map(&:to_i)
    # The advisories whose findings it re-triages, or nil for every finding of its hosts (a full run, or more than
    # ADVISORY_LIMIT advisories).
    def advisory_ids = full? ? nil : scope["advisory_ids"]&.map(&:to_i)

    # Claims, recomputes, records, releases; returns the scope the run keeps (EvaluationRun#fan_out! stores it too).
    # Crash-safe (review of #277, B2, and its re-checks): the run's id is in its stored scope before anything is recorded
    # under it, each slice's changed chunks are recorded in the transaction that changes them, and the prepared scope is
    # stored before the claims are released. So a fan-out run again after a failure, from any point, reaches every host
    # a committed slice changed, and claims not released are claimed again. A run whose job died with its worker (Solid
    # Queue fails a killed worker's job without a retry) is resumed by TriageRunWatchJob: its fan-out or its remaining
    # batches are queued again, at most RESUMES times. A full run resumes rather than restarts: its base pass writes only
    # the verdicts that change, and its batches carry on from those left.
    def prepare!
      return scope if prepared?

      store!(scope.merge("chunk_runs" => (chunk_runs + [ @run_id ]).compact.uniq))
      claimed, kinds, cves, advisories = claim_all
      full = full? || kinds.include?("kev_all")
      advisory_ids = full ? nil : advisories_for(cves, advisories)
      VulnerabilityMatcher::Chunks.signals_barrier! # every match that read the signals before they changed has committed
      chunk_ids = full ? ChunkEvaluation.distinct.pluck(:package_chunk_id) : ChunkMatch.where(advisory_id: advisory_ids).distinct.pluck(:package_chunk_id)
      stats = Hash.new(0)
      record = full ? nil : ->(ids) { record_chunks(ids) }
      changed = chunk_ids.each_slice(CHUNK_BATCH).flat_map { |slice| VulnerabilityTriage::Base.refresh!(slice, advisory_ids:, on_changed: record, stats:) }
      record_sets! unless full
      store!(scope.merge("full" => full, "prepared" => true, "changes" => claimed.size, "advisories" => advisory_ids&.size,
                         "advisory_ids" => (advisory_ids.sort if advisory_ids && advisory_ids.size <= ADVISORY_LIMIT),
                         "chunks_changed" => changed.size, "verdicts_changed" => stats[:verdicts]))
      TriageSignalChange.release!(claimed) if claimed.any?
      scope
    end

    # The hosts on sets holding a chunk the run recorded (triage_run_sets, found once by record_sets!): by their current
    # set, and by the set their findings were last moved from, so a host whose current set is gone or unsupported has
    # its kept findings re-triaged too (review of #277, S3b). range: a batch's host ids, on the hosts and inside both
    # subqueries, so each batch reads only its own range (third review of #277: merging the range with this relation
    # replaced the range condition). Each of a batch's rows probes the run's sets by key, so a batch costs its own range,
    # not a scan of every set holding the chunks (fourth review of #277: that was about 250 ms a batch at 20,000 sets,
    # and grows with the sets, up to 900,000 at a million hosts: ADR 0028). Sets are immutable, so the ones found as the
    # run is prepared are all that hold its chunks; a set made later comes with a report, whose own transitions read
    # the refreshed bases.
    def hosts(range = nil)
      base = range ? Host.in_fleet.where(id: range) : Host.in_fleet
      return base if full?

      current, moved_from = [ HostPackageSet, HostVulnerabilityEvaluation ].map do |model|
        on_run_set = TriageRunSet.where(evaluation_run_id: recorded_runs).where(TriageRunSet.arel_table[:package_set_id].eq(model.arel_table[:package_set_id]))
        rows = model.where(on_run_set.arel.exists)
        range ? rows.where(host_id: range) : rows
      end
      # One IN over a UNION, not two INs joined by OR: the planner can make it a semi-join, where an OR of two subqueries
      # too large to hash (a run reaching most of a million hosts) is read again for every host.
      base.where(Host.arel_table[:id].in(Arel::Nodes::Union.new(current.select(:host_id).arel, moved_from.select(:host_id).arel)))
    end

    # Re-classifies the range's hosts: only the findings of its advisories, or (a full run, or too many advisories) every
    # finding through the hosts' transitions. Returns the hosts whose shown vulnerabilities changed.
    def call(range)
      # Not as a prepared statement: a worker's connection runs it for batch after batch, and PostgreSQL's generic plan
      # (from the sixth run on) cannot see how narrow the range is: a sparse run's batch went from 5 ms to 450 ms.
      ids = Host.connection.unprepared_statement { hosts(range).pluck(:id) }
      advisory_ids ? VulnerabilityMatcher.retriage!(ids, advisory_ids:) : VulnerabilityMatcher.match!(ids).changed_host_ids
    end

    # A run that is not prepared is covered only by a run that carries its id (a retry from its scope), never just
    # because the covering run is full: a run still preparing may refresh after this one has read the bases (review of
    # #277, re-check S2). A prepared run is covered by a full run, or by one that re-runs its chunks for at least its
    # advisories.
    def covers?(other)
      return false unless other.is_a?(Triage)
      return !other.run_id.nil? && chunk_runs.include?(other.run_id) unless other.prepared?
      return true if full?
      return false if other.full? || !(other.chunk_runs - chunk_runs).empty?

      advisory_ids.nil? || (!other.advisory_ids.nil? && (other.advisory_ids - advisory_ids).empty?)
    end

    def refresh_always? = false

    private

    # [claimed ids, kinds, CVE ids, advisory ids], claiming until nothing new comes (a row an import holds locked is
    # read again until it is released, so a repeat ends the loop).
    def claim_all
      seen = Set.new
      rows = []
      loop do
        batch = TriageSignalChange.claim(kinds: reason == "kev" ? AT_ONCE : TriageSignalChange::KINDS, limit: CLAIM).reject { |row| seen.include?(row.id) }
        break if batch.empty?

        seen.merge(batch.map(&:id))
        rows.concat(batch)
        break if batch.size < CLAIM
      end
      [ rows.map(&:id), rows.map(&:kind).uniq, rows.filter_map(&:cve_id).uniq, rows.filter_map(&:advisory_id).uniq ]
    end

    # The advisories naming the CVEs (by id or alias), and those named directly.
    def advisories_for(cves, advisories)
      return advisories if cves.empty?

      named = cves.each_slice(5_000).flat_map do |slice|
        Advisory.where(advisory_id: slice + slice.map { |cve| "DEBIAN-#{cve}" }).or(Advisory.where("aliases && ARRAY[?]::varchar[]", slice)).pluck(:id)
      end
      (named + advisories).uniq
    end

    # Inside a refresh slice's transaction; a retried slice records its chunks again, which changes nothing.
    def record_chunks(ids)
      ids.each_slice(5_000) { |slice| TriageRunChunk.insert_all(slice.map { |id| { evaluation_run_id: @run_id, package_chunk_id: id } }) }
    end

    def recorded_runs = chunk_runs.presence || [ 0 ]

    SETS_SQL = <<~SQL.squish.freeze
      INSERT INTO triage_run_sets (evaluation_run_id, package_set_id)
      SELECT :run, id FROM package_sets
      WHERE chunk_ids && ARRAY(SELECT package_chunk_id FROM triage_run_chunks WHERE evaluation_run_id IN (:runs))::bigint[]
      ON CONFLICT DO NOTHING
    SQL

    # Finds the sets holding the recorded chunks once, through the sets' GIN index, before the prepared scope is
    # stored (so a fan-out run again records them again, idempotently), and analyses the table, so the batches' plans
    # see how many there are.
    def record_sets!
      connection = TriageRunSet.connection
      connection.exec_update(TriageRunSet.sanitize_sql_array([ SETS_SQL, { run: @run_id, runs: recorded_runs } ]))
      connection.execute("ANALYZE triage_run_sets")
    end

    def store!(scope)
      @scope = scope
      EvaluationRun.where(id: @run_id).update_all(scope:, updated_at: Time.current)
    end
  end
end
