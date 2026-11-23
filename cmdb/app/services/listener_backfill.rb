# Writes each finding's listener (VT-SCORES #262, vulnerability_findings.listener) from the listener evidence in force,
# as the hosts' transitions would write it, for the upgrade that added the column (migration 20261123262002, and
# bin/rails compliance_summaries:recount_scores when that refuses): a network listener wins over loopback-only ones,
# on every finding of a package one loads, whatever its bucket, for the evidence the server received less than
# VulnerabilityTriage::LISTENER_FRESH ago (ListenerSource's rule: library_scan ran, loaded_by_listeners not empty). So
# no host is counted, in the recount after it, without its listener points (review of #305, S2). Evidence that
# expires later is cleared by TriageListenerExpiryJob, as always.
#
# Only for hosts that are evaluated now, whose transitions write their findings' listeners; a host that is not (its
# findings kept as they were) keeps NULL until its transitions next run, as it would have without the upgrade (re-check
# of #305, N3). A finding the matcher could not evaluate (an unparsable version) keeps its listener too.
#
# It runs only while the upgrade's recount has not started (needed?): the recount always follows a finished backfill,
# so a recount under way means the backfill is done, and the upgrade never refuses again for it (re-check of #305,
# B1). That is also while the server is down (the migration at container start, or the upgrade step in the waiting
# container), so no report's re-triage runs beside it (S1).
#
# BATCH hosts a statement, each its own transaction with its summary recount (the triggers, ADR 0026), found through
# the partial index on host_applicability, and "in force" read at each statement (N1). Idempotent: run again, it
# writes nothing.
class ListenerBackfill
  BATCH = 1_000
  # The estimate's rate, about three times the 18 ms a host measured with its recount (docs/operations/benchmark.md).
  HOST_SECONDS = 0.05
  EVIDENCE = "ha.library_scan = 'ran' AND jsonb_array_length(ha.loaded_by_listeners) > 0".freeze
  HOSTS = <<~SQL.squish.freeze
    SELECT ha.host_id FROM host_applicability ha
     WHERE #{EVIDENCE} AND EXISTS (SELECT 1 FROM host_vulnerability_evaluations e WHERE e.host_id = ha.host_id AND e.state = 'evaluated')
     ORDER BY ha.host_id
  SQL
  WRITE = <<~SQL.squish.freeze
    UPDATE vulnerability_findings f SET listener = e.listener
      FROM (SELECT ha.host_id, p.package, max(CASE WHEN u ->> 'class' = 'network' THEN 2 ELSE 1 END)::smallint AS listener
              FROM host_applicability ha
              CROSS JOIN LATERAL jsonb_array_elements(ha.loaded_by_listeners) u
              CROSS JOIN LATERAL jsonb_array_elements_text(u -> 'packages') p(package)
             WHERE ha.host_id = ANY (ARRAY[?]::bigint[]) AND #{EVIDENCE} AND ha.library_scan_received_at > ?
             GROUP BY ha.host_id, p.package) e
     WHERE f.host_id = e.host_id AND f.package = e.package AND f.state <> 'resolved' AND f.bucket IS NOT NULL
       AND f.listener IS DISTINCT FROM e.listener
  SQL

  # recount: the upgrade's ComplianceFixRecount, which says whether the backfill is still to do.
  def initialize(recount:, log: ->(_message) { })
    @recount = recount
    @log = log
    @conn = ApplicationRecord.connection
  end

  # Whether to run: the recount is still to do and has not started.
  def needed? = @recount.needed? && @recount.last_host_id.zero?

  # Seconds it would take at HOST_SECONDS, counting the hosts only as far as within (seconds) needs (as
  # ComplianceFixRecount#estimate, N4); 0 when it is not needed.
  def estimate(within: nil)
    return 0.0 unless needed?

    limit = within && ((within / HOST_SECONDS).floor + 1)
    @conn.select_value("SELECT count(*) FROM (#{HOSTS}#{" LIMIT #{limit.to_i}" if limit}) s").to_i * HOST_SECONDS
  end

  # Returns how many findings it wrote (0 when not needed).
  def run!
    return 0 unless needed?

    ids = @conn.select_values(HOSTS).map(&:to_i)
    written = ids.each_slice(BATCH).sum do |slice|
      ApplicationRecord.transaction { @conn.exec_update(ApplicationRecord.sanitize_sql_array([ WRITE, slice, Time.current - VulnerabilityTriage::LISTENER_FRESH ])) }
    end
    @log.call("wrote the listener of #{written} findings on #{ids.size} hosts with listener evidence") if ids.any?
    written
  end
end
