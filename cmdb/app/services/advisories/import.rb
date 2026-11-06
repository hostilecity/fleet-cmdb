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
  #
  # The result's changed_packages, { "Debian:13" => ["openssl"] }, names every package an added, changed,
  # or withdrawn advisory affects or affected, for targeted re-matching (P2-S11).
  class Import
    Result = Data.define(:import, :changed_packages)

    BATCH = 500
    PROBLEM_LIMIT = 100
    COUNTS = %w[records created updated unchanged older withdrawn absent skipped malformed rejected_urls].freeze
    LOCK_KEY = "advisories.import".freeze

    # Records a failed import (nothing was stored), audited, in its own transaction.
    def self.record_failure(origin:, source:, reason:, operator: nil, full: false, started_at: Time.current)
      AdvisoryImport.transaction do
        import = AdvisoryImport.create!(origin:, source:, full:, operator:, state: "failed", reason: reason.truncate(512),
                                        started_at:, finished_at: Time.current)
        Audit.record(actor: operator || Audit::SYSTEM, action: Audit::Actions::ADVISORY_IMPORT_FAILED, target: import,
                     changes: { "origin" => origin, "source" => source, "reason" => import.reason })
        import
      end
    end

    # origin: "feed" or "file". source: the name to show and store (the feed's host and path, or the file
    # name), never a credential.
    def initialize(origin:, source:, full: false, operator: nil, etag: nil, last_modified: nil)
      @origin = origin
      @source = Record.clean_text(source, 256) || "unknown"
      @full = full
      @operator = operator
      @validators = { etag:, last_modified: }
    end

    def call(reader)
      started_at = Time.current
      @counts = COUNTS.index_with(0)
      @problems = []
      @changed = Hash.new { |hash, key| hash[key] = Set.new }
      @seen = Set.new
      @ecosystems = Set.new

      AdvisoryImport.transaction do
        AdvisoryImport.connection.execute("SELECT pg_advisory_xact_lock(hashtext(#{AdvisoryImport.connection.quote(LOCK_KEY)}))")
        reader.each_slice(BATCH) { |entries| store(entries.filter_map { |entry| parse(entry) }) }
        sweep_absent if @full && @counts["malformed"].zero?
        import = AdvisoryImport.create!(origin: @origin, source: @source, full: @full, operator: @operator, state: "succeeded",
                                        ecosystems: @ecosystems.to_a.sort, counts: @counts, problems: @problems, **@validators,
                                        started_at:, finished_at: Time.current)
        Audit.record(actor: @operator || Audit::SYSTEM, action: Audit::Actions::ADVISORY_IMPORTED, target: import,
                     changes: { "origin" => @origin, "source" => @source, "full" => @full, "ecosystems" => import.ecosystems.join(", "), "counts" => @counts })
        Result.new(import:, changed_packages: @changed.to_h { |ecosystem, packages| [ ecosystem, packages.sort ] })
      end
    end

    private

    def parse(entry)
      @counts["records"] += 1
      raise Record::Malformed, entry.problem if entry.problem

      Record.parse(entry.bytes).tap { |record| @counts["rejected_urls"] += record.rejected_urls }
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
        record.package_keys.each { |ecosystem, _| @ecosystems << ecosystem }
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

      stored = Advisory.current.where(id: AdvisoryPackage.where(ecosystem: @ecosystems.to_a).select(:advisory_id)).pluck(:id, :advisory_id)
      absent = stored.reject { |_, advisory_id| @seen.include?(advisory_id) }.map(&:first)
      return if absent.empty?

      absent.each_slice(BATCH) do |ids|
        AdvisoryPackage.where(advisory_id: ids).pluck(:ecosystem, :package).each { |ecosystem, package| @changed[ecosystem] << package }
        Advisory.where(id: ids).update_all(withdrawn_at: Time.current, withdrawn_reason: "absent", updated_at: Time.current)
      end
      @counts["absent"] = absent.size
    end
  end
end
