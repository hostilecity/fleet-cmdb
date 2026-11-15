# One host's compliance counts and the fleet list's sort keys (#193): its CIS-aligned pass, fail, and not readable
# counts, open failures by severity, open and reopened findings by severity, whether matching evaluated it, and copies
# of the host's name, hostname, tags, agent version, enrollment state, liveness, and operating system. The fleet list
# and the compliance page read pages of these rows in index order, and the fleet-wide counts are one sum over them.
#
# Written only by the database: triggers note the hosts a transaction changed, and a deferred constraint trigger syncs
# and recounts them at commit (db/migrate/20261110193000_create_host_compliance_summaries.rb, ADR 0026), whichever
# code writes. An advisory's new severity queues its hosts in host_compliance_recounts instead, for drain_recounts!
# (ComplianceSummaryRecountJob), so an import never holds their rows. rebuild! and drift are for operators, through
# bin/rails compliance_summaries:rebuild and compliance_summaries:check (docs/operations/compliance-summaries.md).
class HostComplianceSummary < ApplicationRecord
  self.primary_key = :host_id

  BATCH_SIZE = 1_000

  belongs_to :host

  def readonly? = true

  # Recounts every host from its rows, creating any missing summary row, in batches of hosts, each in its own short
  # transaction, and empties the recount queue for them. Returns the number of hosts.
  def self.rebuild!(batch_size: BATCH_SIZE)
    count = 0
    Host.in_batches(of: batch_size) do |batch|
      ids = batch.ids.sort
      transaction do
        recompute(ids)
        connection.execute(sanitize_sql_array([ "DELETE FROM host_compliance_recounts WHERE host_id IN (?)", ids ]))
      end
      count += ids.size
    end
    count
  end

  # The ids of hosts whose summary row is missing or differs from a fresh count of their rows, leaving out hosts
  # queued for a recount (they are known to be behind). Each batch's rows are locked before they are read, so a
  # change committing meanwhile is not taken for drift, then recomputed inside a transaction that is rolled back:
  # this writes nothing.
  def self.drift(batch_size: BATCH_SIZE)
    queued = connection.select_values("SELECT host_id FROM host_compliance_recounts").to_set
    Host.in_batches(of: batch_size).flat_map do |batch|
      ids = batch.ids.sort
      drifted = []
      transaction do
        before = lock.where(host_id: ids).order(:host_id).to_a.to_h { |row| [ row.host_id, row.attributes ] }
        recompute(ids)
        after = rows(ids)
        drifted = ids.reject { |id| queued.include?(id) || (before[id] && before[id] == after[id]) }
        raise ActiveRecord::Rollback
      end
      drifted
    end
  end

  # Hosts waiting in the recount queue.
  def self.queued = connection.select_value("SELECT count(*) FROM host_compliance_recounts").to_i

  # Recounts the queued hosts in batches, lowest id first, each batch in its own transaction, and returns how many.
  # Batches taken by another run at the same time are skipped, not waited for.
  def self.drain_recounts!(batch_size: BATCH_SIZE)
    total = 0
    loop do
      ids = transaction do
        taken = connection.select_values(sanitize_sql_array([ <<~SQL.squish, batch_size ])).map(&:to_i)
          DELETE FROM host_compliance_recounts WHERE host_id IN
            (SELECT host_id FROM host_compliance_recounts ORDER BY host_id LIMIT ? FOR UPDATE SKIP LOCKED) RETURNING host_id
        SQL
        connection.execute(sanitize_sql_array([ "SELECT host_compliance_summaries_refresh(ARRAY[?]::bigint[])", taken.sort ])) if taken.any?
        taken
      end
      break if ids.empty?

      total += ids.size
    end
    total
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
