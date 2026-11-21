# Exploitation signals (VT-SIGNALS, FR-2.6, ADR 0032 point 5): CISA's Known Exploited Vulnerabilities catalog and
# FIRST's EPSS scores, fetched by the server only (agents need no internet access), with the advisory feeds'
# safeguards: verified HTTPS through Advisories::Feed, size and time limits, conditional requests, a truncation guard,
# freshness, an offline import task, and audit.
#
# - Signals::KevReader and Signals::KevImport read and store the KEV catalog (VT-S02).
# - Signals::EpssReader and Signals::EpssImport stream and store EPSS scores for the CVEs stored advisories name, with
#   the hysteresis band (VT-S03).
# - KevRefreshJob and EpssRefreshJob download them on a schedule; Signals::Freshness says how old each is.
# - What changed is handed to the triage run through TriageSignalChange (VT-S05, #259). A signal never opens,
#   resolves, or reopens a finding or changes its severity, and stale or missing data never rewrites anything (B1).
module Signals
  KEV = "kev".freeze
  EPSS = "epss".freeze
  # FIRST's usage terms ask for this attribution where EPSS is shown (VT-S03).
  EPSS_ATTRIBUTION = "See EPSS at https://www.first.org/epss".freeze
  CVE = DebianTriage::Releases::CVE

  # The CVE ids stored advisories name: an advisory's own id without "DEBIAN-", and its aliases (as FindingTriage
  # looks them up), as SQL yielding one cve_id column.
  ADVISORY_CVES = <<~SQL.squish.freeze
    SELECT DISTINCT c.cve_id FROM advisories a
    CROSS JOIN LATERAL unnest(array_append(a.aliases, regexp_replace(a.advisory_id, '^DEBIAN-', ''))) AS c(cve_id)
    WHERE c.cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'
  SQL

  module_function

  def config = Rails.configuration.x.signals

  def kev_feed
    Advisories::Feed.new(url: config.kev_url, token: nil, max_bytes: config.kev_max_download_bytes, label: "CISA KEV catalog",
                         accept: "application/json", suffix: ".json", redirect_hosts: [])
  end

  def epss_feed
    Advisories::Feed.new(url: config.epss_url, token: nil, max_bytes: EpssReader::MAX_COMPRESSED_BYTES, label: "FIRST EPSS download",
                         accept: "application/gzip, application/octet-stream", suffix: ".csv.gz",
                         redirect_hosts: config.epss_redirect_hosts, redirect_setting: "FLEET_EPSS_REDIRECT_HOSTS")
  end

  def url_for(signal) = signal == KEV ? config.kev_url : config.epss_url

  def feed_for(signal) = signal == KEV ? kev_feed : epss_feed

  # Seconds one statement of an import may take, and that its transaction may sit idle between statements (while the
  # reader parses a batch), so an import can never hold a snapshot open for long and keep vacuum back for the whole
  # database (review of #269). The EPSS reader's own DEADLINE bounds the reading.
  STATEMENT_TIMEOUT = 300
  IDLE_TIMEOUT = 60

  # Takes the lock a signal's imports are serialised by, until the current transaction ends, then limits the rest of
  # the transaction (SET LOCAL, so a pooled connection is never left changed). The staging tables stay inside the
  # transaction for the same reason: a temporary table across transactions would not survive a transaction pooler.
  def lock!(signal)
    connection = SignalImport.connection
    connection.execute("SELECT pg_advisory_xact_lock(hashtext(#{connection.quote("signals.#{signal}.import")}))")
    connection.execute("SET LOCAL statement_timeout = '#{STATEMENT_TIMEOUT}s'")
    connection.execute("SET LOCAL idle_in_transaction_session_timeout = '#{IDLE_TIMEOUT}s'")
  end

  # The database ended the import's connection (its idle_in_transaction_session_timeout fired, or the server went away),
  # which rolled the import back. Recorded as a failed import with this reason, by the refresh job and the rake tasks.
  CONNECTION_ERRORS = [ PG::ConnectionBad, ActiveRecord::ConnectionNotEstablished, ActiveRecord::ConnectionFailed ].freeze
  CONNECTION_LOST = "the database ended the import's connection (for example after #{IDLE_TIMEOUT} s idle inside its transaction), " \
                    "so nothing was imported".freeze

  def connection_lost?(error) = CONNECTION_ERRORS.any? { |klass| error.is_a?(klass) }

  # Reopens the connection after connection_lost?, so the failure can be recorded.
  def reconnect! = SignalImport.connection.reconnect!

  # Records an import that stored nothing (the download or the file could not be read), audited, in its own transaction.
  def record_failure(signal, reason:, origin:, source:, operator: nil, started_at: Time.current)
    SignalImport.transaction do
      import = SignalImport.create!(signal:, origin:, source: Advisories::Record.clean_text(source, 256) || "unknown", operator:, state: "failed",
                                    reason: reason.truncate(512), started_at:, finished_at: Time.current)
      action = signal == KEV ? Audit::Actions::SIGNAL_KEV_IMPORT_FAILED : Audit::Actions::SIGNAL_EPSS_IMPORT_FAILED
      Audit.record(actor: operator || Audit::SYSTEM, action:, target: import, changes: { "origin" => origin, "source" => import.source, "reason" => import.reason })
      import
    end
  end

  # Deletes a signal's stored data (bin/rails signals:kev_clear and signals:epss_reset): the only way it is ever
  # deleted, since stale or turned-off data keeps being used (B1). Audited, with what it means; returns the SignalImport
  # recording it (state cleared), after which freshness reads "never imported" and, for EPSS, a file of any date
  # imports again (the way out of a wrong stored score date).
  #
  # KEV: rules N1 and I5 stop applying, so every finding is handed to the triage run (kev_all). EPSS: the CVEs that
  # were high are handed over (epss), since rule N2 stops applying to them.
  CLEARED = {
    KEV => "KEV entries deleted: rule N1 (known exploited) and rule I5 (Debian unimportant is ignorable once KEV data exists) " \
           "stop applying until KEV data is imported again",
    EPSS => "EPSS scores deleted: rule N2 stops applying until EPSS is imported again, and the next file is imported whatever its score date"
  }.freeze
  CLEAR_TASKS = { KEV => "bin/rails signals:kev_clear", EPSS => "bin/rails signals:epss_reset" }.freeze

  def clear!(signal, operator: nil)
    SignalImport.transaction do
      lock!(signal)
      now = Time.current
      if signal == KEV
        deleted = KevEntry.delete_all
        TriageSignalChange.record!(:kev_all)
      else
        TriageSignalChange.record!(:epss, cve_ids: EpssScore.where(band: "high").pluck(:cve_id))
        deleted = EpssScore.delete_all
      end
      import = SignalImport.create!(signal:, origin: "task", source: CLEAR_TASKS.fetch(signal), operator:, state: "cleared",
                                    counts: { "deleted" => deleted }, reason: CLEARED.fetch(signal), started_at: now, finished_at: now)
      action = signal == KEV ? Audit::Actions::SIGNAL_KEV_CLEARED : Audit::Actions::SIGNAL_EPSS_CLEARED
      Audit.record(actor: operator || Audit::SYSTEM, action:, target: import, changes: { "counts" => import.counts, "reason" => import.reason })
      import
    end
  end

  # How many of the signal's CVEs (every KEV entry, or the EPSS high band) match open findings, stored on the import for
  # the Data sources panels, so a page view never counts findings (reviews of #269). It runs in SignalMatchCountJob,
  # queued once the import has committed (count_later), so a slow or failing count can never hold up an import, keep an
  # operator's terminal, or turn a stored import into a failed one. added: the CVEs a KEV import added (at most
  # ADDED_LIMIT are passed to the job), counted the same way.
  #
  # The import's counts say what happened, with matching_at: matching_state "counted" (and matching, added_matching),
  # "timed_out" (a statement passed MATCHING_TIMEOUT: too large to count at this fleet's size), or "failed" (any other
  # error, after the job's retries). bin/rails signals:recount counts the latest imports again.
  MATCHING_TIMEOUT = 300
  ADDED_LIMIT = 10_000
  MATCHING_KEYS = %w[matching added_matching matching_state matching_at matching_error].freeze

  # Queues the count after an import commits. Never raises: the import is stored whatever happens here.
  def count_later(import, added: nil)
    return unless import.state == "succeeded"

    SignalMatchCountJob.perform_later(import.id, (added if added && added.size <= ADDED_LIMIT))
  rescue StandardError => e
    Rails.logger.error("[signals] could not queue the matching count for #{import.signal} import #{import.id}: #{e.class.name}: #{e.message}")
  end

  # Counts and stores. A timeout is stored as such; any other error is raised, for the job to retry, and stored by
  # record_count_failure! after the last attempt.
  def count_matching!(import, added: nil)
    sql = import.signal == KEV ? "SELECT cve_id FROM kev_entries" : "SELECT cve_id FROM epss_scores WHERE band = 'high'"
    counts = { "matching" => matching_open_findings(sql) }
    counts["added_matching"] = matching_open_findings(added) if added
    store_count(import, counts.merge("matching_state" => "counted"))
  rescue ActiveRecord::QueryCanceled
    Rails.logger.warn("[signals] counting the #{import.signal} CVEs that match open findings took longer than #{MATCHING_TIMEOUT} s; stopped")
    store_count(import, "matching_state" => "timed_out")
  end

  def record_count_failure!(import, error)
    Rails.logger.error("[signals] counting the #{import.signal} CVEs that match open findings failed: #{error.class.name}: #{error.message}")
    store_count(import, "matching_state" => "failed", "matching_error" => error.class.name)
  end

  def store_count(import, counts)
    import.update_columns(counts: import.counts.except(*MATCHING_KEYS).merge(counts, "matching_at" => Time.current.utc.iso8601))
    import
  end
  private_class_method :store_count

  # The way to count again (bin/rails signals:recount): the latest import that stored data, per signal. Returns the
  # imports queued.
  def recount_later
    [ KEV, EPSS ].filter_map do |signal|
      cleared = SignalImport.where(signal:, state: "cleared").maximum(:finished_at)
      scope = SignalImport.where(signal:).succeeded.where("counts ->> 'not_modified' IS NULL")
      scope = scope.where(SignalImport.arel_table[:finished_at].gt(cleared)) if cleared
      scope.order(finished_at: :desc, id: :desc).first&.tap { |import| SignalMatchCountJob.perform_later(import.id, nil) }
    end
  end

  # How many of the given CVEs a stored advisory with an open or reopened finding names, for the data sources page and
  # the import counts. cves: an Array of CVE ids, or SQL selecting one cve_id column.
  #
  # Each CVE is looked up (advisory_id by its unique index, aliases by their GIN index), then each advisory found gets
  # one index probe for an open finding (LATERAL ... LIMIT 1, so a poor row estimate cannot turn it into a scan of every
  # finding). Measured on 74,000 advisories and 4 million findings: 19 ms for 1,800 KEV CVEs, about 30 microseconds a
  # CVE. JIT is off for the statement: its compile time (about 190 ms) was ten times the query's.
  def matching_open_findings(cves)
    connection = SignalImport.connection
    if cves.is_a?(Array)
      return 0 if cves.empty?

      cves = "SELECT unnest(#{connection.quote(PG::TextEncoder::Array.new.encode(cves))}::varchar[])"
    end
    # Run outside any transaction (SignalMatchCountJob), so this block is a transaction of its own and its SET LOCAL
    # settings end with it. Inside an outer transaction it would be a savepoint, and they would last until the outer one ends.
    SignalImport.transaction(requires_new: true) do
      connection.execute("SET LOCAL jit = off")
      connection.execute("SET LOCAL statement_timeout = '#{MATCHING_TIMEOUT}s'")
      connection.select_value(<<~SQL.squish).to_i
        WITH k AS (SELECT DISTINCT cve_id FROM (#{cves}) AS s(cve_id)),
        named AS (
          SELECT a.id, k.cve_id FROM k JOIN advisories a ON a.advisory_id IN ('DEBIAN-' || k.cve_id, k.cve_id)
          UNION
          SELECT a.id, k.cve_id FROM k JOIN advisories a ON a.aliases @> ARRAY[k.cve_id]::varchar[])
        SELECT count(DISTINCT n.cve_id) FROM named n
        CROSS JOIN LATERAL (SELECT 1 FROM vulnerability_findings f WHERE f.advisory_id = n.id AND f.state IN ('open', 'reopened') LIMIT 1) AS open
      SQL
    end
  end

  # Whether a feed's ALLOW_DROPS ceiling or the share guard holds an import back. allowed: nil for no confirmation,
  # else the operator's ceiling (a count).
  def too_many_dropped?(dropped:, stored:, allowed:)
    return dropped > allowed.to_i unless allowed.nil?

    dropped > stored * Advisories.config.withdraw_share
  end
end
