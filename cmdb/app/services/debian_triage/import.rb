module DebianTriage
  # Stores the Debian Security Tracker's triage from a Reader (P2-S16, ADR 0022) and audits the import.
  #
  # - Only the releases in the release table (DebianTriage::Releases) are kept, and only CVE ids, which are what
  #   the advisories join on; the tracker's other ids (TEMP-...) and other releases are counted, not stored.
  # - Per release, source package, and CVE it keeps the status, urgency (normalised, with the raw text), fixed
  #   version, no-DSA note and reason, next_point_update, and the CVE's scope. An entry or a release's data
  #   that is not in that shape is skipped and counted as malformed, with where it was (the first PROBLEM_LIMIT).
  # - The document is read once, into a temporary table (with COPY), and each release's stored data is then replaced from it
  #   in the same transaction, so readers see a release's old data or its new data, never a mix. A document that
  #   cannot be read at all (Advisories::Unreadable) stores nothing.
  # - Truncation guard (as the OSV withdrawal guard, review of #131): a release whose stored entries the document
  #   would drop more than Advisories.config.withdraw_share of (FLEET_ADVISORY_WITHDRAW_SHARE, 10%) keeps its
  #   previous data, and the import is held back with the counts. The other releases are stored. allowed_drops
  #   ({ "trixie" => 9000 }, an operator's confirmation from the rake tasks) is a ceiling, not a bypass: once one
  #   is given, each release may drop at most its allowed count (none for a release it does not name).
  # - A release taken out of the release table has its stored data deleted: the fleet no longer uses it.
  # - It never touches findings, advisories, or matching: triage is an annotation (ADR 0022, item 3).
  class Import
    LOCK_KEY = "debian_triage.import".freeze
    BATCH = 1_000
    PROBLEM_LIMIT = 100
    STAGING = "triage_staging".freeze
    COLUMNS = %w[release package cve_id status urgency urgency_raw fixed_version no_dsa no_dsa_note no_dsa_reason next_point_update scope].freeze
    PACKAGE = /\A[a-z0-9][a-z0-9+.~-]{0,127}\z/
    SCOPES = %w[local remote].freeze
    COPY_ENCODER = PG::TextEncoder::CopyRow.new

    # An entry, or one release's data in it, that is not in the tracker's shape: skipped and counted.
    class Malformed < StandardError; end

    # Records an import that stored nothing (the document could not be downloaded or read), audited, in its own
    # transaction.
    def self.record_failure(reason:, origin:, source:, operator: nil, started_at: Time.current)
      TriageImport.transaction do
        import = TriageImport.create!(tracker: TRACKER, origin:, source:, operator:, state: "failed", reason: reason.truncate(512),
                                      started_at:, finished_at: Time.current)
        Audit.record(actor: operator || Audit::SYSTEM, action: Audit::Actions::ADVISORY_TRIAGE_IMPORT_FAILED, target: import,
                     changes: { "origin" => origin, "source" => source, "reason" => import.reason })
        import
      end
    end

    # origin: "feed" or "file". source: the feed's host and path, or the file name.
    def initialize(origin:, source:, operator: nil, etag: nil, last_modified: nil, allowed_drops: {})
      @origin = origin
      @source = Advisories::Record.clean_text(source, 256) || "unknown"
      @operator = operator
      @validators = { etag:, last_modified: }
      @allowed_drops = allowed_drops.to_h.transform_keys(&:to_s)
    end

    def call(reader)
      started_at = Time.current
      @releases = Releases.names
      @counts = { "packages" => 0, "entries" => 0, "other_ids" => 0, "other_releases" => 0, "malformed" => 0, "repeated" => 0 }
      @problems = []
      @rows = []

      TriageImport.transaction do
        connection.execute("SELECT pg_advisory_xact_lock(hashtext(#{connection.quote(LOCK_KEY)}))")
        create_staging
        reader.each { |package| read(package) }
        flush
        outcomes = replace_releases
        held = outcomes.select { |_, o| o["outcome"] == "held_back" }.keys
        @counts["releases"] = outcomes
        @counts["removed_releases"] = remove_unlisted
        import = TriageImport.create!(tracker: TRACKER, origin: @origin, source: @source, operator: @operator, state: held.any? ? "held_back" : "succeeded",
                                      releases: @releases - held, counts: @counts, problems: @problems, reason: held.any? ? held_reason(outcomes, held) : nil,
                                      **@validators, started_at:, finished_at: Time.current)
        action = held.any? ? Audit::Actions::ADVISORY_TRIAGE_IMPORT_HELD_BACK : Audit::Actions::ADVISORY_TRIAGE_IMPORTED
        Audit.record(actor: @operator || Audit::SYSTEM, action:, target: import,
                     changes: { "origin" => @origin, "source" => @source, "counts" => @counts, "reason" => import.reason }.compact)
        connection.execute("DROP TABLE #{STAGING}")
        import
      end
    end

    private

    def connection = TriageEntry.connection

    # Dropped first: an import that raised inside an enclosing transaction (a spec's) leaves it behind.
    def create_staging
      connection.execute("DROP TABLE IF EXISTS #{STAGING}")
      connection.execute(<<~SQL.squish)
        CREATE TEMPORARY TABLE #{STAGING} (release varchar(32) NOT NULL, package varchar(128) NOT NULL, cve_id varchar(32) NOT NULL,
          status varchar(16) NOT NULL, urgency varchar(16), urgency_raw varchar(64), fixed_version varchar(256), no_dsa boolean NOT NULL,
          no_dsa_note varchar(512), no_dsa_reason varchar(32), next_point_update boolean NOT NULL, scope varchar(8),
          seq bigserial) ON COMMIT DROP
      SQL
    end

    def read(package)
      @counts["packages"] += 1
      name = package.package
      return problem(name, nil, "is not a valid source package name") unless name.is_a?(String) && name.match?(PACKAGE)
      return problem(name, nil, package.problem) if package.problem

      package.entries.each do |id, entry|
        @counts["entries"] += 1
        next @counts["other_ids"] += 1 unless id.match?(Releases::CVE)

        rows(name, id, entry)
      end
    end

    def rows(package, cve_id, entry)
      raise Malformed, "is not an object with a releases object" unless entry.is_a?(Hash) && entry["releases"].is_a?(Hash)

      scope = SCOPES.include?(entry["scope"]) ? entry["scope"] : nil
      entry["releases"].each do |release, data|
        next @counts["other_releases"] += 1 unless @releases.include?(release)

        @rows << [ release, package, cve_id, *triage(data), scope ]
        flush if @rows.size >= BATCH
      rescue Malformed => e
        problem(package, cve_id, "#{release}: #{e.message}")
      end
    rescue Malformed => e
      problem(package, cve_id, e.message)
    end

    # status, urgency, urgency_raw, fixed_version, no_dsa, no_dsa_note, no_dsa_reason, next_point_update.
    def triage(data)
      raise Malformed, "is not an object" unless data.is_a?(Hash)

      status = data["status"]
      raise Malformed, "has no status of open, resolved, or undetermined" unless TriageEntry::STATUSES.include?(status)

      raw = text(data["urgency"], 64, "urgency")
      urgency = raw.to_s.downcase.sub(/\**\z/, "").strip # "low*": the stars are kept in urgency_raw
      no_dsa = data.key?("nodsa")
      [ status, (TriageEntry::URGENCIES.include?(urgency) ? urgency : nil), raw, text(data["fixed_version"], 256, "fixed_version"), no_dsa,
        no_dsa ? text(data["nodsa"], 512, "nodsa").presence : nil, no_dsa ? text(data["nodsa_reason"], 32, "nodsa_reason").presence : nil,
        data["next_point_update"] == true ]
    end

    def text(value, limit, field)
      return nil if value.nil?
      raise Malformed, "has a #{field} that is not a string of at most #{limit} characters" unless value.is_a?(String) && value.length <= limit

      Advisories::Record.clean_text(value, limit) || ""
    end

    def problem(package, cve_id, message)
      @counts["malformed"] += 1
      @problems << { "package" => package.to_s.truncate(128), "id" => cve_id, "problem" => message }.compact if @problems.size < PROBLEM_LIMIT
    end

    def flush
      return if @rows.empty?

      raw = connection.raw_connection
      raw.copy_data("COPY #{STAGING} (#{COLUMNS.join(', ')}) FROM STDIN", COPY_ENCODER) { @rows.each { |row| raw.put_copy_data(row) } }
      @rows.clear
    end

    # Per release: how many entries are stored, how many the document has, how many it would drop, and whether it
    # replaced them or was held back.
    def replace_releases
      tracker = connection.quote(TRACKER)
      stored = TriageEntry.where(tracker: TRACKER, release: @releases).group(:release).count
      connection.execute("CREATE INDEX ON #{STAGING} (release, package, cve_id)")
      # An entry repeated in the document (a source package's key given twice) counts once, and the first is kept.
      rows = connection.select_rows("SELECT release, count(DISTINCT (package, cve_id)), count(*) FROM #{STAGING} GROUP BY release")
      @counts["repeated"] = rows.sum { |_, distinct, all| all - distinct }
      incoming = rows.to_h { |release, distinct, _| [ release, distinct ] }
      dropped = connection.select_rows(<<~SQL.squish).to_h
        SELECT e.release, count(*) FROM triage_entries e
        WHERE e.tracker = #{tracker} AND NOT EXISTS
          (SELECT 1 FROM #{STAGING} s WHERE s.release = e.release AND s.package = e.package AND s.cve_id = e.cve_id)
        GROUP BY e.release
      SQL
      @releases.to_h do |release|
        counts = { "stored" => stored.fetch(release, 0), "in_file" => incoming.fetch(release, 0), "dropped" => dropped.fetch(release, 0) }
        if too_many_dropped?(release, counts)
          next [ release, counts.merge("outcome" => "held_back") ]
        end

        quoted = connection.quote(release)
        TriageEntry.where(tracker: TRACKER, release:).delete_all
        connection.execute("INSERT INTO triage_entries (tracker, #{COLUMNS.join(', ')}) SELECT DISTINCT ON (package, cve_id) #{tracker}, #{COLUMNS.join(', ')} " \
                           "FROM #{STAGING} WHERE release = #{quoted} ORDER BY package, cve_id, seq")
        [ release, counts.merge("outcome" => "replaced") ]
      end
    end

    def too_many_dropped?(release, counts)
      return counts["dropped"] > @allowed_drops.fetch(release, 0).to_i if @allowed_drops.any?

      counts["dropped"] > counts["stored"] * Advisories.config.withdraw_share
    end

    def remove_unlisted
      TriageEntry.where(tracker: TRACKER).where.not(release: @releases).group(:release).count.each_key.to_h do |release|
        [ release, TriageEntry.where(tracker: TRACKER, release:).delete_all ]
      end
    end

    def held_reason(outcomes, held)
      parts = held.map { |release| "#{outcomes[release]['dropped']} of #{outcomes[release]['stored']} stored #{release} entries" }
      "the document would drop #{parts.to_sentence}, so #{held.size == 1 ? 'that release keeps its' : 'those releases keep their'} previous data"
    end
  end
end
