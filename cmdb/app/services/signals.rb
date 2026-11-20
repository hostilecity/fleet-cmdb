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

  # Takes the lock a signal's imports are serialised by, until the current transaction ends.
  def lock!(signal)
    connection = SignalImport.connection
    connection.execute("SELECT pg_advisory_xact_lock(hashtext(#{connection.quote("signals.#{signal}.import")}))")
  end

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

  # Deletes the stored KEV entries (bin/rails signals:kev_clear, VT-S02): the only way they are ever deleted, since
  # stale or turned-off data keeps being used (B1). Rules N1 and I5 stop applying, so every finding is handed to the
  # triage run (kev_all). Audited, with what it means; returns the SignalImport recording it.
  CLEARED = "KEV entries deleted: rule N1 (known exploited) and rule I5 (Debian unimportant is ignorable once KEV data exists) " \
            "stop applying until KEV data is imported again".freeze

  def clear_kev!(operator: nil)
    SignalImport.transaction do
      lock!(KEV)
      now = Time.current
      deleted = KevEntry.delete_all
      TriageSignalChange.record!(:kev_all)
      import = SignalImport.create!(signal: KEV, origin: "task", source: "bin/rails signals:kev_clear", operator:, state: "cleared",
                                    counts: { "deleted" => deleted }, reason: CLEARED, started_at: now, finished_at: now)
      Audit.record(actor: operator || Audit::SYSTEM, action: Audit::Actions::SIGNAL_KEV_CLEARED, target: import,
                   changes: { "counts" => import.counts, "reason" => CLEARED })
      import
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
    SignalImport.transaction do
      connection.execute("SET LOCAL jit = off")
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
