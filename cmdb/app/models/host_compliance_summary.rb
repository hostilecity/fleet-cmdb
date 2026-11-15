# One host's compliance counts and the fleet list's sort keys (#193): its CIS-aligned pass, fail, and not readable
# counts, open failures by severity, open and reopened findings by severity, whether matching evaluated it, and copies
# of the host's name, hostname, tags, agent version, enrollment state, liveness, and operating system. The fleet list
# and the compliance page read pages of these rows in index order, and the fleet-wide counts are one sum over them.
#
# Written only by the database: triggers keep every row right in the transaction that changes what it is built from
# (db/migrate/20261110193000_create_host_compliance_summaries.rb), whichever code writes it. rebuild! and drift are for
# operators, through bin/rails compliance_summaries:rebuild and compliance_summaries:check
# (docs/operations/compliance-summaries.md).
class HostComplianceSummary < ApplicationRecord
  self.primary_key = :host_id

  BATCH_SIZE = 1_000

  belongs_to :host

  def readonly? = true

  # Recounts every host from its rows, creating any missing summary row, in batches of hosts, each in its own short
  # transaction. Returns the number of hosts.
  def self.rebuild!(batch_size: BATCH_SIZE)
    count = 0
    Host.in_batches(of: batch_size) do |batch|
      ids = batch.ids.sort
      transaction { recompute(ids) }
      count += ids.size
    end
    count
  end

  # The ids of hosts whose summary row is missing or differs from a fresh count of their rows. Each batch is
  # recomputed inside a transaction that is rolled back, so this writes nothing.
  def self.drift(batch_size: BATCH_SIZE)
    Host.in_batches(of: batch_size).flat_map do |batch|
      ids = batch.ids.sort
      drifted = []
      transaction do
        before = rows(ids)
        recompute(ids)
        after = rows(ids)
        drifted = ids.reject { |id| before[id] && before[id] == after[id] }
        raise ActiveRecord::Rollback
      end
      drifted
    end
  end

  # The host fields first (creating a missing row), then the counts: the database functions the triggers call.
  def self.recompute(ids)
    %w[host_compliance_summaries_sync host_compliance_summaries_refresh].each do |function|
      connection.execute(sanitize_sql_array([ "SELECT #{function}(ARRAY[?]::bigint[])", ids ]))
    end
  end

  def self.rows(ids) = where(host_id: ids).to_a.to_h { |row| [ row.host_id, row.attributes ] }

  private_class_method :recompute, :rows
end
