# Deletes snapshots, report ids, and status events past the retention window (NFR-2, DEC-07, P1-S10), in
# batches, keeping each host's newest snapshot and status event. Audit entries are not touched. Then collects the
# package sets and chunks no host, kept snapshot, or vulnerability evaluation references any more (PackageStore.collect!,
# ADR 0028 decision 8), including those of snapshot partitions PartitionMaintenanceJob dropped since (ADR 0027).
# Scheduled daily in config/recurring.yml. `dry_run: true` only logs the counts.
class RetentionPruneJob < ApplicationJob
  def perform(dry_run: false)
    Retention.prune!(dry_run:)
    PackageStore.collect!(dry_run:)
  end
end
