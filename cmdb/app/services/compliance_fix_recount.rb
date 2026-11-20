# The one-time recount of every host's compliance summary after the fix counts were added (VT-FIXABLE #256,
# migrations 20261120256001 and 20261120256002), resumable, with an estimate of what is left (as #196's
# PackageStoreBackfill, review of #267, S3).
#
# Progress is the last host id recounted, in compliance_fix_recounts (one row, made by 20261120256001 and dropped by
# 20261120256002 once every host is done), so a run that stops, by an interrupt, a timeout, or a restarted container,
# carries on where it stopped. Hosts are recounted in id order, BATCH at a time, each batch in its own transaction
# that runs host_compliance_summaries_refresh (which locks the batch's summary rows in host order, as every flush
# does) and moves the progress row, so a summary flush for those hosts waits for at most one batch: 0.8 s measured
# for 100 hosts with 3,560 open findings each. A recount is idempotent: a row already right is not rewritten.
class ComplianceFixRecount
  TABLE = "compliance_fix_recounts".freeze
  BATCH = 100
  LOG_EVERY = 10_000 # hosts
  # The estimate's rates, about three times those measured on 2 shared CPUs (docs/operations/benchmark.md, "Fix counts
  # on the summaries"): 0.17 ms a host and about 1.6 microseconds an open finding there.
  HOST_SECONDS = 0.0005
  FINDING_SECONDS = 0.000005

  Estimate = Data.define(:seconds, :hosts, :findings, :complete) do
    def complete? = complete
  end

  def initialize(log: ->(_message) { })
    @log = log
    @conn = ApplicationRecord.connection
  end

  # Whether there is a recount to do: the progress row exists until the migration that finishes it drops it.
  def needed? = @conn.table_exists?(TABLE)

  def last_host_id = @conn.select_value("SELECT last_host_id FROM compliance_fix_recounts WHERE id = 1").to_i

  # The time the hosts left would take. With within (seconds), it counts only far enough to tell that the time is past
  # it, and then says it stopped counting (complete: false), so it reads little of a large database.
  def estimate(within: nil)
    return Estimate.new(seconds: 0.0, hosts: 0, findings: 0, complete: true) unless needed?

    after = last_host_id
    host_limit = within && ((within / HOST_SECONDS).floor + 1)
    hosts = bounded("SELECT 1 FROM hosts WHERE id > ?", after, host_limit)
    return Estimate.new(seconds: hosts * HOST_SECONDS, hosts:, findings: 0, complete: false) if host_limit && hosts >= host_limit

    finding_limit = within && (((within - hosts * HOST_SECONDS) / FINDING_SECONDS).floor + 1)
    findings = bounded("SELECT 1 FROM vulnerability_findings WHERE state IN ('open', 'reopened') AND host_id > ?", after, finding_limit)
    Estimate.new(seconds: hosts * HOST_SECONDS + findings * FINDING_SECONDS, hosts:, findings:, complete: !(finding_limit && findings >= finding_limit))
  end

  # Recounts every host after the progress row's, BATCH at a time; returns how many it recounted.
  def run!(batch: BATCH)
    return 0 unless needed?

    @conn.execute("INSERT INTO compliance_fix_recounts (id, last_host_id) VALUES (1, 0) ON CONFLICT (id) DO NOTHING")
    done = 0
    loop do
      ids = @conn.select_values(sql("SELECT id FROM hosts WHERE id > ? ORDER BY id LIMIT ?", last_host_id, batch)).map(&:to_i)
      break if ids.empty?

      ApplicationRecord.transaction do
        @conn.execute(sql("SELECT host_compliance_summaries_refresh(ARRAY[?]::bigint[])", ids))
        @conn.execute(sql("UPDATE compliance_fix_recounts SET last_host_id = ? WHERE id = 1", ids.last))
      end
      done += ids.size
      @log.call("#{done} hosts recounted, up to host #{ids.last}") if done / LOG_EVERY > (done - ids.size) / LOG_EVERY
    end
    @log.call("every host recounted (#{done} in this run)")
    done
  end

  private

  # count(*) of a query with one bound value, read at most limit rows deep (no limit: all of them).
  def bounded(query, value, limit) = @conn.select_value(sql("SELECT count(*) FROM (#{query} LIMIT ?) s", value, limit)).to_i

  def sql(*parts) = ApplicationRecord.sanitize_sql_array(parts)
end
