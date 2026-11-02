# Deletes snapshots, report ids, and status events past the retention window (NFR-2, DEC-07, P1-S10), in
# batches, keeping each host's newest snapshot and status event. Audit entries are not touched. Scheduled
# daily in config/recurring.yml. `dry_run: true` only logs the counts.
class RetentionPruneJob < ApplicationJob
  queue_as :default

  def perform(dry_run: false)
    Retention.prune!(dry_run:)
  end
end
