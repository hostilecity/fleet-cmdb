# Moves the stored package lists into content-addressed sets (#196, ADR 0028): PackageStoreBackfill, which says how.
#
# It runs here, at container start (bin/docker-entrypoint runs db:prepare), only when the work is small enough to finish
# well inside the deploy's wait for /up: at most INLINE_HASHES distinct package lists and INLINE_FINDINGS findings to
# copy (a homelab takes seconds). Above that it refuses with UPGRADE_STEP, before it writes anything, and the operator
# runs `bin/rails packages:backfill` in a one-off container, then starts the server again
# (docs/operations/upgrades.md). The entrypoint recognises the refusal and waits instead of exiting, so the container
# does not restart into it again and again.
#
# Rolling back clears the store (sets, chunks, verdicts) and the pointers to it; the old storage is still there until
# DropHostPackages.
class BackfillPackageSets < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  INLINE_HASHES = 5_000
  INLINE_FINDINGS = 1_000_000
  # The text bin/docker-entrypoint looks for.
  UPGRADE_STEP = "fleet-cmdb upgrade step needed".freeze

  def up
    backfill = PackageStoreBackfill.new(log: ->(message) { say(message, true) })
    left = backfill.pending
    if left["hashes"] > INLINE_HASHES || left["findings"] > INLINE_FINDINGS
      raise "#{UPGRADE_STEP}: #{left['hashes']} distinct package lists and #{left['findings']} findings to move into package sets is too " \
            "long for container start. Nothing was changed by this step. Run `bin/rails packages:backfill` in a one-off container with this " \
            "image, then start the server again (docs/operations/upgrades.md)."
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
