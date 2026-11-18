# Hourly partition maintenance (ADR 0027, #195, P1-S10): creates the history tables' partitions ahead, then retires
# the partitions past the retention window (Retention.retire!), moving each host's newest row forward first. Does no
# DDL while a backup of the database runs; work it cannot do now is done by a later run. Also run once at boot, after
# db:prepare (lib/tasks/partitions.rake). `dry_run: true` creates nothing and only counts what would be retired.
class PartitionMaintenanceJob < ApplicationJob
  def perform(dry_run: false)
    Partitions.maintain!(dry_run:)
  end
end
