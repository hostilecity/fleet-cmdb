# Writes each finding's listener (VT-SCORES #262, vulnerability_findings.listener) from the listener evidence in force,
# as the hosts' transitions would write it, for the upgrade that added the column (migration 20261123262002, and
# bin/rails compliance_summaries:recount_scores when that refuses): a network listener wins over loopback-only ones,
# on every finding of a package one loads, whatever its bucket, for the evidence the server received less than
# VulnerabilityTriage::LISTENER_FRESH ago. So no host is counted, in the recount after it, without its listener points
# (review of #305, S2). Evidence that expires later is cleared by TriageListenerExpiryJob, as always.
#
# BATCH hosts a statement, each its own transaction with its summary recount (the triggers, ADR 0026), found through
# the partial index on host_applicability. Idempotent: run again, it writes nothing.
class ListenerBackfill
  BATCH = 1_000
  # The estimate's rate, about three times the 18 ms a host measured with its recount (docs/operations/benchmark.md).
  HOST_SECONDS = 0.05
  HOSTS = "SELECT host_id FROM host_applicability WHERE library_scan = 'ran' AND jsonb_array_length(loaded_by_listeners) > 0 ORDER BY host_id".freeze
  WRITE = <<~SQL.squish.freeze
    UPDATE vulnerability_findings f SET listener = e.listener
      FROM (SELECT ha.host_id, p.package, max(CASE WHEN u ->> 'class' = 'network' THEN 2 ELSE 1 END)::smallint AS listener
              FROM host_applicability ha
              CROSS JOIN LATERAL jsonb_array_elements(ha.loaded_by_listeners) u
              CROSS JOIN LATERAL jsonb_array_elements_text(u -> 'packages') p(package)
             WHERE ha.host_id = ANY (ARRAY[?]::bigint[]) AND ha.library_scan_received_at > ?
             GROUP BY ha.host_id, p.package) e
     WHERE f.host_id = e.host_id AND f.package = e.package AND f.state <> 'resolved' AND f.bucket IS NOT NULL
       AND f.listener IS DISTINCT FROM e.listener
  SQL

  def initialize(log: ->(_message) { })
    @log = log
    @conn = ApplicationRecord.connection
  end

  def host_ids = @conn.select_values(HOSTS).map(&:to_i)

  # Seconds the backfill would take at HOST_SECONDS.
  def estimate = host_ids.size * HOST_SECONDS

  # Returns how many findings it wrote.
  def run!(now: Time.current)
    ids = host_ids
    written = ids.each_slice(BATCH).sum do |slice|
      ApplicationRecord.transaction { @conn.exec_update(ApplicationRecord.sanitize_sql_array([ WRITE, slice, now - VulnerabilityTriage::LISTENER_FRESH ])) }
    end
    @log.call("wrote the listener of #{written} findings on #{ids.size} hosts with listener evidence") if ids.any?
    written
  end
end
