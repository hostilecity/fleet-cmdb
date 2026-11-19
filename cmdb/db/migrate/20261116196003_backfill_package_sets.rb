# Moves the stored package lists into content-addressed sets (#196, ADR 0028): PackageStoreBackfill, which says how.
#
# It runs here, at container start (bin/docker-entrypoint runs db:prepare), only when its estimated time
# (PackageStoreBackfill#estimate, from measured rates) is at most INLINE_SECONDS, which leaves the boot, the
# temporary indexes, DropHostPackages, and a margin inside the deploy's 5-minute wait for /up (a homelab takes
# seconds). Above that it refuses with UPGRADE_STEP, before it writes anything: the entrypoint recognises the refusal
# and keeps the container up without serving, so it does not restart into it again and again, and the operator runs
# the backfill in that waiting container (docs/operations/upgrades.md), then restarts it.
#
# Rolling back clears the store (sets, chunks, verdicts) and the pointers to it; the old storage is still there until
# DropHostPackages.
class BackfillPackageSets < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  INLINE_SECONDS = 90
  # The text bin/docker-entrypoint looks for.
  UPGRADE_STEP = "fleet-cmdb upgrade step needed".freeze
  RUNBOOK = "On the server VM, as the deploy user, run the backfill in this waiting container under the backup lock: " \
            "nohup ~/.local/share/fleet-cmdb/backup/package-backfill.sh > ~/packages-backfill.log 2>&1 & (docs/operations/upgrades.md).".freeze

  def up
    backfill = PackageStoreBackfill.new(log: ->(message) { say(message, true) })
    estimate = backfill.estimate(within: INLINE_SECONDS)
    if estimate.seconds > INLINE_SECONDS
      counted = estimate.counts.map { |what, count| "#{count} #{what.tr('_', ' ')}" }.join(", ")
      raise "#{UPGRADE_STEP}: moving the package lists into package sets would take more than #{INLINE_SECONDS} s (counted so far: #{counted}; " \
            "about #{(estimate.seconds / 60).ceil} minutes or more), too long for container start; nothing was changed by this step. #{RUNBOOK}"
    end
    backfill.run!
  end

  def down
    execute "UPDATE host_package_sets SET package_set_id = NULL"
    execute "UPDATE package_snapshots SET package_set_id = NULL"
    execute "UPDATE host_vulnerability_evaluations SET package_set_id = NULL"
    %w[chunk_matches chunk_evaluations package_sets package_chunk_entries package_chunks].each { |table| execute "DELETE FROM #{table}" }
  end
end
