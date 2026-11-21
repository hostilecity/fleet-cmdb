# Recounts every host's compliance summary after 20261120256001 added the fix counts (VT-FIXABLE #256): the resumable
# ComplianceFixRecount, then drops its progress row.
#
# It runs here, at container start (bin/docker-entrypoint runs db:prepare, before the server serves), only when its
# estimate (ComplianceFixRecount#estimate, from measured rates) is at most INLINE_SECONDS, well inside the deploy's
# 5-minute wait for /up (a homelab takes seconds). Above that it refuses with UPGRADE_STEP before it recounts anything,
# as #196's BackfillPackageSets does: the entrypoint keeps the container up without serving, and the operator runs
# bin/rails compliance_summaries:recount_fixes in it, then restarts it (docs/operations/upgrades.md); this migration
# then finds nothing left and finishes at once (review of #267, S3).
#
# Outside a transaction: each batch of 100 hosts commits with its progress, so a recount that stops partway carries on
# where it stopped when this runs again, and 20261120256001's DDL is never undone by it.
class RecountFixFlagsInSummaries < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  INLINE_SECONDS = 90
  # The text bin/docker-entrypoint looks for (as BackfillPackageSets').
  UPGRADE_STEP = "fleet-cmdb upgrade step needed".freeze
  RUNBOOK = "On the server VM, as the deploy user, recount in this waiting container, then restart it: " \
            "docker exec fleet-cmdb bin/rails compliance_summaries:recount_fixes && docker restart fleet-cmdb (docs/operations/upgrades.md).".freeze

  def up
    recount = ComplianceFixRecount.new(log: ->(message) { say(message, true) })
    estimate = recount.estimate(within: INLINE_SECONDS)
    if estimate.seconds > INLINE_SECONDS
      raise "#{UPGRADE_STEP}: recounting every host's vulnerability fix counts would take #{too_long(estimate)}, too long for container start; " \
            "the counts read 0 until then. #{RUNBOOK}"
    end
    recount.run!
    drop_table :compliance_fix_recounts, if_exists: true
  end

  def too_long(estimate)
    return "about #{(estimate.seconds / 60).ceil} min" if estimate.complete?

    "more than #{INLINE_SECONDS} s (it stopped counting there; docs/operations/upgrades.md has the rates)"
  end

  def down
    # The progress row comes back at its start, so migrating up again recounts every host.
    require_relative "20261120256001_add_fix_counts_to_compliance_summaries"
    AddFixCountsToComplianceSummaries.new.create_progress unless table_exists?(:compliance_fix_recounts)
  end
end
