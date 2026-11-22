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
  # - A failed run can be started again (the Data sources page): its scope names the chunks it recorded, so the new run
  #   re-runs the same hosts without claiming again, and supersedes it. A later run covers an earlier one only when it
  #   re-runs every host the earlier one would (its chunks, or all), so latest-wins never drops a host.
  class Triage
    AT_ONCE = %w[kev kev_all advisory].freeze
    REASONS = %w[kev daily all repair].freeze
    CLAIM = 1_000
    CHUNK_BATCH = 5_000
    # Up to this many advisories, the run re-triages only their findings on each host (VulnerabilityMatcher.retriage!,
    # about 1 ms a host); above it (a first tracker import names most of them), each host's transitions run in full,
    # about 80 ms a host at 4,450 findings: 21 thread-hours at a million hosts, as the migration's full run costs. The
    # advisory ids are kept in the run's scope, so the limit also bounds that row.
    ADVISORY_LIMIT = 20_000

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
    # The advisories whose findings it re-triages, or nil for every finding of its hosts (a full run, more than
    # ADVISORY_LIMIT advisories, or a dead run adopted that had more).
    def advisory_ids = full? || scope["all_findings"] ? nil : scope["advisory_ids"]&.map(&:to_i)

    # Claims, recomputes, records, releases; returns the scope the run keeps (EvaluationRun#fan_out! stores it too).
    # Crash-safe (review of #277, B2, and its re-check): the run's id is in its stored scope before anything is recorded
    # under it, each slice's changed chunks are recorded in the transaction that changes them, and the prepared scope is
    # stored before the claims are released. A run that died with its job (a killed worker: Solid Queue fails the job
    # without a retry) is failed by TriageRunWatchJob, and the next triage run adopts every failed one: their recorded
    # chunks and advisories become its own, so it re-runs their hosts, and it supersedes them. Claims a dead run had
    # not released are pending still, and claimed again.
    def prepare!
      return scope if prepared?

      adopted = adoptable
      store!(scope.merge("chunk_runs" => (chunk_runs + adopted.flat_map(&:chunk_runs) + adopted.map(&:run_id) + [ @run_id ]).compact.uniq))
      claimed, kinds, cves, advisories = claim_all
      full = full? || kinds.include?("kev_all") || adopted.any?(&:full?)
      advisory_ids = full ? nil : (advisories_for(cves, advisories) + adopted.select(&:prepared?).flat_map { |run| run.advisory_ids || [] }).uniq
      all_findings = !full && adopted.any? { |run| run.prepared? && run.advisory_ids.nil? }
      VulnerabilityMatcher::Chunks.signals_barrier! # every match that read the signals before they changed has committed
      chunk_ids = full ? ChunkEvaluation.distinct.pluck(:package_chunk_id) : ChunkMatch.where(advisory_id: advisory_ids).distinct.pluck(:package_chunk_id)
      stats = Hash.new(0)
      record = full ? nil : ->(ids) { record_chunks(ids) }
      changed = chunk_ids.each_slice(CHUNK_BATCH).flat_map { |slice| VulnerabilityTriage::Base.refresh!(slice, advisory_ids:, on_changed: record, stats:) }
      store!(scope.merge("full" => full, "prepared" => true, "changes" => claimed.size, "advisories" => advisory_ids&.size,
                         "advisory_ids" => (advisory_ids.sort if advisory_ids && advisory_ids.size <= ADVISORY_LIMIT), "all_findings" => all_findings,
                         "adopted" => adopted.map(&:run_id), "chunks_changed" => changed.size, "verdicts_changed" => stats[:verdicts]))
      TriageSignalChange.release!(claimed) if claimed.any?
      scope
    end

    # The older triage runs that failed (their job raised every retry, or died with its worker) and that no run has
    # superseded yet.
    def adoptable
      return [] unless @run_id

      EvaluationRun.where(kind: "triage", state: "failed").where(id: ...@run_id).order(:id).map { |run| Triage.new(run.scope, run.id) }
    end

    # The hosts on sets holding a chunk the run (or a run it adopted) recorded: by their current set, and by the set
    # their findings were last moved from, so a host whose current set is gone or unsupported has its kept findings
    # re-triaged too (review of #277, S3b).
    def hosts
      return Host.in_fleet if full?

      sets = PackageSet.where("chunk_ids && ARRAY(SELECT package_chunk_id FROM triage_run_chunks WHERE evaluation_run_id IN (?))::bigint[]", chunk_runs.presence || [ 0 ])
      Host.in_fleet.where(id: HostPackageSet.where(package_set_id: sets.select(:id)).select(:host_id))
          .or(Host.in_fleet.where(id: HostVulnerabilityEvaluation.where(package_set_id: sets.select(:id)).select(:host_id)))
    end

    # Re-classifies the range's hosts: only the findings of its advisories, or (a full run, or too many advisories) every
    # finding through the hosts' transitions. Returns the hosts whose shown vulnerabilities changed.
    def call(range)
      ids = Host.in_fleet.where(id: range).merge(hosts).pluck(:id)
      advisory_ids ? VulnerabilityMatcher.retriage!(ids, advisory_ids:) : VulnerabilityMatcher.match!(ids).changed_host_ids
    end

    # A run that is not prepared is covered only by a run that carries its id (one that adopted it, or a retry from its
    # scope), never just because the covering run is full: a run still preparing may refresh after this one has read
    # the bases, and its hosts would then never be re-triaged (review of #277, re-check S2). A prepared run is covered by
    # a full run, or by one that re-runs its chunks for at least its advisories.
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

    def store!(scope)
      @scope = scope
      EvaluationRun.where(id: @run_id).update_all(scope:, updated_at: Time.current)
    end
  end
end
