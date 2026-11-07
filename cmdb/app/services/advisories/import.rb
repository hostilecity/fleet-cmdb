module Advisories
  # Stores the advisories from a Reader (P2-S10, DEC-11), in one transaction, and audits the import.
  #
  # - Idempotent by advisory id and modified: a record whose modified time equals the stored one changes
  #   nothing, and an older one is ignored, so importing the same data twice, or an old archive after a new
  #   one, never moves data backwards. A newer record replaces the advisory and its packages.
  # - A malformed record (Record::Malformed, or a document the Reader could not read) is reported with where
  #   it was and why, and skipped; the valid records still import. This is the choice the spec left to
  #   DEC-11: OSV data is one record per file, so one bad file should not hold back a release's other
  #   advisories. Input that cannot be read at all (Unreadable) imports nothing: the transaction rolls back.
  # - Records with nothing for the fleet's ecosystems are skipped, unless the advisory is stored already: then
  #   the new version replaces it, so an advisory that stops naming a package stops matching it.
  # - Withdrawn advisories are kept and marked. A full import (the scheduled refresh, or FULL=1 for a complete
  #   archive imported by hand) is the whole data set for the ecosystems it has records for: an advisory stored
  #   for one of them that the import does not contain is marked withdrawn as "absent", because OSV moves
  #   withdrawn records out of the ecosystem's archive. That sweep is skipped when any record was malformed,
  #   since the missing advisory may be the one that could not be read.
  # - With guard_withdrawals (a full import uploaded on the dashboard, P2-D06, review of #129), the sweep is
  #   counted per ecosystem before anything is written. If it would withdraw more than WITHDRAW_SHARE of an
  #   ecosystem's current advisories, or any of them when the file has fewer than SMALL_FILE_RECORDS records for
  #   it, the import raises WithdrawalsRefused with the counts and the transaction rolls back, unless
  #   allowed_withdrawals (the operator's second confirmation) names at least that many for the ecosystem.
  # - time_limit bounds how long reading and storing may take once the lock is held, and lock_timeout how long
  #   to wait for the lock; past the time limit the import is Unreadable and rolls back.
  #
  # The result's changed_packages, { "Debian:13" => ["openssl"] }, names every package an added, changed,
  # or withdrawn advisory affects or affected; VulnerabilityMatchJob re-matches them once the import commits (P2-S11).
  class Import
    Result = Data.define(:import, :changed_packages)

    BATCH = 500
    PROBLEM_LIMIT = 100
    COUNTS = %w[records created updated unchanged older withdrawn absent skipped malformed rejected_urls].freeze
    LOCK_KEY = "advisories.import".freeze

    # A guarded full import would withdraw more than WITHDRAW_SHARE of an ecosystem's advisories.
    WITHDRAW_SHARE = 0.10
    # A guarded full import with fewer records than this for an ecosystem may withdraw none of it unconfirmed.
    SMALL_FILE_RECORDS = 1_000

    # The queued or importing row this import was to finish has been finished meanwhile (AdvisoryUploadPruneJob
    # failed it): nothing is written.
    class Abandoned < StandardError; end

    # A guarded full import would withdraw too many advisories; nothing is written. withdrawals:
    # { "Debian:13" => { "withdraw" => 38_000, "current" => 38_412, "records" => 1 } } for every ecosystem it
    # would withdraw advisories of.
    class WithdrawalsRefused < StandardError
      attr_reader :withdrawals

      def initialize(withdrawals)
        @withdrawals = withdrawals
        parts = withdrawals.map do |ecosystem, w|
          "#{w['withdraw']} of #{w['current']} current #{ecosystem} advisories (the file has #{w['records']} #{w['records'] == 1 ? 'record' : 'records'} for it)"
        end
        super("this full import would mark #{parts.to_sentence} withdrawn, which resolves the findings they produced; nothing was imported")
      end
    end

    # Records a failed import (nothing was stored), audited, in its own transaction. import: a queued or
    # importing row to finish as failed (an upload imported in the background, P2-D06) instead of a new one.
    # counts: what to keep on the failed row (the withdrawals a guarded full import refused).
    def self.record_failure(reason:, origin: nil, source: nil, operator: nil, full: false, started_at: Time.current, import: nil, counts: {})
      AdvisoryImport.transaction do
        failed = { state: "failed", reason: reason.truncate(512), finished_at: Time.current, counts: }
        if import
          # Locked and checked again: an import finished meanwhile keeps its outcome.
          return import unless import.lock!.in_progress?

          import.update!(failed)
        else
          import = AdvisoryImport.create!(origin:, source:, full:, operator:, started_at:, **failed)
        end
        Audit.record(actor: import.operator || Audit::SYSTEM, action: Audit::Actions::ADVISORY_IMPORT_FAILED, target: import,
                     changes: { "origin" => import.origin, "source" => import.source, "reason" => import.reason, **counts })
        import
      end
    end

    # origin: "feed" or "file". source: the name to show and store (the feed's host and path, or the file
    # name), never a credential. record: a queued or importing AdvisoryImport to finish with the result (an
    # upload imported in the background, P2-D06); its origin, source, full, and operator are used.
    def initialize(origin: nil, source: nil, full: false, operator: nil, etag: nil, last_modified: nil, record: nil,
                   guard_withdrawals: false, allowed_withdrawals: {})
      @guard_withdrawals = guard_withdrawals
      @allowed_withdrawals = allowed_withdrawals.to_h
      @record = record
      @origin = record&.origin || origin
      @source = record&.source || Record.clean_text(source, 256) || "unknown"
      @full = record ? record.full : full
      @operator = record ? record.operator : operator
      @validators = { etag:, last_modified: }
    end

    # time_limit and lock_timeout: seconds, or nil for none (the feed and the rake task).
    def call(reader, time_limit: nil, lock_timeout: nil)
      started_at = Time.current
      @counts = COUNTS.index_with(0)
      @problems = []
      @changed = Hash.new { |hash, key| hash[key] = Set.new }
      @seen = Set.new
      @ecosystems = Set.new
      @ecosystem_records = Hash.new(0)

      AdvisoryImport.transaction do
        connection = AdvisoryImport.connection
        # set_config(..., true) is SET LOCAL: it ends with this transaction.
        connection.execute("SELECT set_config('lock_timeout', #{connection.quote("#{Integer(lock_timeout)}s")}, true)") if lock_timeout
        connection.execute("SELECT pg_advisory_xact_lock(hashtext(#{connection.quote(LOCK_KEY)}))")
        @deadline = time_limit && Process.clock_gettime(Process::CLOCK_MONOTONIC) + time_limit
        @time_limit = time_limit
        reader.each_slice(BATCH) do |entries|
          check_deadline!
          store(entries.filter_map { |entry| parse(entry) })
        end
        check_deadline!
        sweep_absent if @full && @counts["malformed"].zero?
        outcome = { state: "succeeded", ecosystems: @ecosystems.to_a.sort, counts: @counts, problems: @problems, **@validators, finished_at: Time.current }
        raise Abandoned, "advisory import #{@record.id} was finished meanwhile" if @record && !@record.lock!.in_progress?

        import = @record ? @record.tap { |r| r.update!(outcome) } : AdvisoryImport.create!(origin: @origin, source: @source, full: @full, operator: @operator, started_at:, **outcome)
        Audit.record(actor: @operator || Audit::SYSTEM, action: Audit::Actions::ADVISORY_IMPORTED, target: import,
                     changes: { "origin" => @origin, "source" => @source, "full" => @full, "ecosystems" => import.ecosystems.join(", "), "counts" => @counts })
        changed = @changed.to_h { |ecosystem, packages| [ ecosystem, packages.sort ] }
        # Targeted re-matching (P2-S11), after commit; it also evaluates hosts that had no advisory data yet.
        VulnerabilityMatchJob.after_import(changed) if changed.any? || @ecosystems.any?
        Result.new(import:, changed_packages: changed)
      end
    end

    private

    def check_deadline!
      return unless @deadline && Process.clock_gettime(Process::CLOCK_MONOTONIC) > @deadline

      raise Unreadable, "#{@source} took longer than #{@time_limit / 60} minutes to import, so nothing was imported; import it on the server with bin/rails advisories:import"
    end

    def parse(entry)
      @counts["records"] += 1
      raise Record::Malformed, entry.problem if entry.problem

      begin
        Record.parse(entry.bytes).tap { |record| @counts["rejected_urls"] += record.rejected_urls }
      rescue StandardError => e
        # A shape Record did not anticipate must not roll back the whole import (review of #103).
        raise e if e.is_a?(Record::Malformed)

        raise Record::Malformed, "could not be read (#{e.class.name})"
      end
    rescue Record::Malformed => e
      @counts["malformed"] += 1
      @problems << { "location" => entry.location, "id" => id_of(entry), "problem" => e.message } if @problems.size < PROBLEM_LIMIT
      nil
    end

    # The id of a malformed record, when it has a valid one, so the operator can look it up.
    def id_of(entry)
      entry.bytes && Record.id_of(JSON.parse(entry.bytes.dup.force_encoding(Encoding::UTF_8)))
    rescue JSON::ParserError, EncodingError
      nil
    end

    def store(records)
      # The newest version of each id in the batch; an id repeated across batches is compared with what the
      # earlier batch stored, in the same transaction.
      records = records.group_by(&:advisory_id).map { |_, versions| versions.max_by(&:modified_at) }
      existing = Advisory.where(advisory_id: records.map(&:advisory_id)).index_by(&:advisory_id)
      changes = records.select do |record|
        @seen << record.advisory_id
        record.package_keys.map(&:first).uniq.each do |ecosystem|
          @ecosystems << ecosystem
          @ecosystem_records[ecosystem] += 1
        end
        @newest = [ @newest, record.modified_at ].compact.max
        classify(record, existing[record.advisory_id])
      end
      write(changes, existing) if changes.any?
    end

    # Counts the record and says whether it needs writing.
    def classify(record, stored)
      outcome =
        if stored.nil? then record.packages.empty? ? "skipped" : "created"
        elsif stored.modified_at > record.modified_at then "older"
        elsif stored.modified_at == record.modified_at && stored.withdrawn_reason != "absent" then "unchanged"
        else "updated"
        end
      @counts[outcome] += 1
      @counts["withdrawn"] += 1 if record.withdrawn? && %w[created updated].include?(outcome) && stored&.withdrawn_reason != "withdrawn"
      %w[created updated].include?(outcome)
    end

    def write(records, existing)
      now = Time.current
      old_keys = AdvisoryPackage.where(advisory_id: existing.values_at(*records.map(&:advisory_id)).compact.map(&:id))
                                .pluck(:ecosystem, :package)
      (old_keys + records.flat_map(&:package_keys)).each { |ecosystem, package| @changed[ecosystem] << package }

      rows = records.map do |r|
        { advisory_id: r.advisory_id, source: @source, summary: r.summary, aliases: r.aliases, severity: r.severity, severity_raw: r.severity_raw,
          reference_url: r.reference_url, published_at: r.published_at, modified_at: r.modified_at, withdrawn_at: r.withdrawn_at,
          withdrawn_reason: (r.withdrawn? ? "withdrawn" : nil), created_at: now, updated_at: now }
      end
      ids = Advisory.upsert_all(rows, unique_by: :advisory_id, returning: %i[id advisory_id], record_timestamps: false,
                                      update_only: rows.first.keys - %i[advisory_id created_at]).rows.to_h(&:reverse)
      AdvisoryPackage.where(advisory_id: ids.values).delete_all
      packages = records.flat_map do |r|
        r.packages.map { |p| { advisory_id: ids.fetch(r.advisory_id), ecosystem: p.ecosystem, package: p.package, ranges: p.ranges, fixed_version: p.fixed_version } }
      end
      AdvisoryPackage.insert_all(packages) if packages.any?
    end

    # Marks withdrawn, as absent, the current advisories of the imported ecosystems that this full import did
    # not contain.
    def sweep_absent
      return if @ecosystems.empty?

      # Only advisories no newer than the newest record here: an older archive, or an older download that
      # imports after a newer one, cannot know about advisories published since, so their absence proves
      # nothing (review of #103).
      stored = Advisory.current.where(id: AdvisoryPackage.where(ecosystem: @ecosystems.to_a).select(:advisory_id))
                       .where(modified_at: ..@newest).pluck(:id, :advisory_id)
      absent = stored.reject { |_, advisory_id| @seen.include?(advisory_id) }.map(&:first)
      return if absent.empty?

      check_withdrawals!(absent) if @guard_withdrawals

      absent.each_slice(BATCH) do |ids|
        AdvisoryPackage.where(advisory_id: ids).pluck(:ecosystem, :package).each { |ecosystem, package| @changed[ecosystem] << package }
        Advisory.where(id: ids).update_all(withdrawn_at: Time.current, withdrawn_reason: "absent", updated_at: Time.current)
      end
      @counts["absent"] = absent.size
    end

    # Refuses a guarded full import that would withdraw too much of an ecosystem (see the class comment), before
    # the sweep writes: raising rolls back the records stored so far too.
    def check_withdrawals!(absent)
      withdraw = AdvisoryPackage.where(advisory_id: absent, ecosystem: @ecosystems.to_a).group(:ecosystem).distinct.count(:advisory_id)
      current = Advisory.current.joins(:packages).where(advisory_packages: { ecosystem: withdraw.keys }).group("advisory_packages.ecosystem").distinct.count(:id)
      withdrawals = withdraw.sort.to_h do |ecosystem, count|
        [ ecosystem, { "withdraw" => count, "current" => current.fetch(ecosystem, 0), "records" => @ecosystem_records[ecosystem] } ]
      end
      too_many = withdrawals.any? do |ecosystem, w|
        next false if w["withdraw"] <= @allowed_withdrawals[ecosystem].to_i

        w["withdraw"] > w["current"] * WITHDRAW_SHARE || w["records"] < SMALL_FILE_RECORDS
      end
      raise WithdrawalsRefused, withdrawals if too_many
    end
  end
end
