module Signals
  # Stores FIRST's EPSS scores from an EpssReader (VT-S03, ADR 0032) and audits the import.
  #
  # - The file is streamed into a temporary table with COPY, so memory is bounded by a batch, not the file (about
  #   300,000 rows). Only the CVEs stored advisories name are kept (Signals::ADVISORY_CVES), a CVE listed twice keeping
  #   its first row; the stored scores are replaced in the same transaction.
  # - Band, with hysteresis (owner decision 6): "high" at a score of at least FLEET_EPSS_ENTER (0.10); a CVE already
  #   high stays high until its score falls below FLEET_EPSS_LEAVE (0.07); otherwise "normal".
  # - A file whose score date is older than the stored scores' is refused (Older) and stores nothing.
  # - Truncation guard, as KEV's: a file that would drop more than FLEET_ADVISORY_WITHDRAW_SHARE (10%) of the stored
  #   scores stores nothing and is held back with its counts; allowed_drops (ALLOW_DROPS) is a ceiling.
  # - The CVEs whose band changed between high and not high (or that gained or lost a high score) are handed to the
  #   daily triage run (TriageSignalChange kind epss), in SQL. Nothing here touches a finding.
  # - The transaction is limited (Signals.lock!), and how many high-band CVEs match open findings is counted after it
  #   commits, by a job (Signals.count_later), so the panel never counts findings on a page view.
  class EpssImport
    STAGING = "epss_staging".freeze
    KEPT = "epss_kept".freeze
    CHANGED = "epss_changed".freeze
    BATCH = 5_000
    COPY_ENCODER = PG::TextEncoder::CopyRow.new

    # The file's scores are older than the stored ones: nothing is stored.
    class Older < StandardError; end

    def initialize(origin:, source:, operator: nil, etag: nil, last_modified: nil, allowed_drops: nil)
      @origin = origin
      @source = Advisories::Record.clean_text(source, 256) || "unknown"
      @operator = operator
      @validators = { etag:, last_modified: }
      @allowed_drops = allowed_drops
    end

    def call(reader)
      started_at = Time.current
      SignalImport.transaction do
        Signals.lock!(EPSS)
        stage(reader)
        stored_date = Signals::Freshness.stored_score_date
        if stored_date && reader.score_date < stored_date
          raise Older, "the file's scores are of #{reader.score_date.iso8601}, older than the stored scores of #{stored_date.iso8601}, so nothing was imported"
        end

        counts = keep(reader)
        held = Signals.too_many_dropped?(dropped: counts["dropped"], stored: counts["stored"], allowed: @allowed_drops)
        counts.merge!(replace(reader.score_date)) unless held
        drop_staging
        import = SignalImport.create!(signal: EPSS, origin: @origin, source: @source, operator: @operator, state: held ? "held_back" : "succeeded",
                                      version: reader.model_version, score_date: reader.score_date, counts:, problems: reader.problems,
                                      reason: (held_reason(counts) if held), **@validators, started_at:, finished_at: Time.current)
        Audit.record(actor: @operator || Audit::SYSTEM, action: held ? Audit::Actions::SIGNAL_EPSS_IMPORT_HELD_BACK : Audit::Actions::SIGNAL_EPSS_IMPORTED,
                     target: import, changes: { "origin" => @origin, "source" => @source, "version" => reader.model_version,
                                                "score_date" => reader.score_date.iso8601, "counts" => counts, "reason" => import.reason }.compact)
        import
      end.tap { |import| Signals.count_later(import) }
    end

    private

    def connection = EpssScore.connection

    # Streams the file's rows into the staging table.
    def stage(reader)
      drop_staging # an import that raised inside an enclosing transaction (a spec's) leaves them behind
      connection.execute("CREATE TEMPORARY TABLE #{STAGING} (cve_id varchar(32) NOT NULL, score numeric NOT NULL, percentile numeric NOT NULL, " \
                         "seq bigserial) ON COMMIT DROP")
      raw = connection.raw_connection
      batch = []
      flush = lambda do
        raw.copy_data("COPY #{STAGING} (cve_id, score, percentile) FROM STDIN", COPY_ENCODER) { batch.each { |row| raw.put_copy_data(row) } }
        batch.clear
      end
      reader.each do |row|
        batch << row
        flush.call if batch.size >= BATCH
      end
      flush.call if batch.any?
    end

    # The rows for CVEs stored advisories name, and how many stored scores the file would drop.
    def keep(reader)
      connection.execute("CREATE TEMPORARY TABLE #{KEPT} ON COMMIT DROP AS SELECT DISTINCT ON (s.cve_id) s.cve_id, s.score, s.percentile " \
                         "FROM #{STAGING} s JOIN (#{ADVISORY_CVES}) c ON c.cve_id = s.cve_id ORDER BY s.cve_id, s.seq")
      connection.execute("CREATE UNIQUE INDEX ON #{KEPT} (cve_id)")
      in_file, distinct = connection.select_rows("SELECT count(*), count(DISTINCT cve_id) FROM #{STAGING}").first.map(&:to_i)
      { "rows" => reader.rows, "valid" => in_file, "malformed" => reader.malformed, "repeated" => in_file - distinct,
        "kept" => connection.select_value("SELECT count(*) FROM #{KEPT}").to_i, "stored" => EpssScore.count,
        "dropped" => connection.select_value("SELECT count(*) FROM epss_scores e WHERE NOT EXISTS (SELECT 1 FROM #{KEPT} k WHERE k.cve_id = e.cve_id)").to_i }
    end

    # Replaces the stored scores with the kept rows and their bands, and hands the band changes to the triage run.
    def replace(score_date)
      enter = connection.quote(Signals.config.epss_enter)
      leave = connection.quote(Signals.config.epss_leave)
      date = connection.quote(score_date.iso8601)
      connection.execute(<<~SQL.squish)
        CREATE TEMPORARY TABLE epss_next ON COMMIT DROP AS
        SELECT k.cve_id, k.score, k.percentile,
               CASE WHEN k.score >= #{enter} OR (e.band = 'high' AND k.score >= #{leave}) THEN 'high' ELSE 'normal' END AS band,
               e.band AS old_band
        FROM #{KEPT} k LEFT JOIN epss_scores e ON e.cve_id = k.cve_id
      SQL
      # The band changes, kept in SQL: a CVE whose band moved between high and not high, or a high CVE the file drops.
      connection.execute(<<~SQL.squish)
        CREATE TEMPORARY TABLE #{CHANGED} ON COMMIT DROP AS
        SELECT cve_id, band = 'high' AS rose FROM epss_next WHERE (band = 'high') IS DISTINCT FROM (coalesce(old_band, 'normal') = 'high')
        UNION ALL
        SELECT e.cve_id, false FROM epss_scores e WHERE e.band = 'high' AND NOT EXISTS (SELECT 1 FROM epss_next n WHERE n.cve_id = e.cve_id)
      SQL
      rose, fell = connection.select_rows("SELECT count(*) FILTER (WHERE rose), count(*) FILTER (WHERE NOT rose) FROM #{CHANGED}").first.map(&:to_i)
      connection.execute("INSERT INTO triage_signal_changes (id, kind, cve_id, created_at) " \
                         "SELECT #{TriageSignalChange::NEXT_ID}, 'epss', cve_id, now() FROM #{CHANGED} " \
                         "ON CONFLICT #{TriageSignalChange::CVE_TARGET} #{TriageSignalChange::ON_CONFLICT_SET}")
      connection.execute("DELETE FROM epss_scores")
      connection.execute("INSERT INTO epss_scores (cve_id, score, percentile, band, score_date) SELECT cve_id, score, percentile, band, #{date} FROM epss_next")
      connection.execute("DROP TABLE epss_next")
      connection.execute("DROP TABLE #{CHANGED}")
      { "high" => EpssScore.where(band: "high").count, "rose" => rose, "fell" => fell }
    end

    def drop_staging
      connection.execute("DROP TABLE IF EXISTS #{KEPT}")
      connection.execute("DROP TABLE IF EXISTS #{STAGING}")
      connection.execute("DROP TABLE IF EXISTS epss_next")
      connection.execute("DROP TABLE IF EXISTS #{CHANGED}")
    end

    def held_reason(counts)
      "the file would drop #{counts['dropped']} of #{counts['stored']} stored scores, so the previous scores are kept"
    end
  end
end
