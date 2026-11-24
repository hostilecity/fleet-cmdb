# The per-host compliance summaries behind the fleet list and the compliance page (#193). Database triggers keep them
# right; these are for an operator who wants to check that, or to rebuild them after restoring data written with
# triggers off (docs/operations/compliance-summaries.md). Both read every host in batches of 1,000, each in its own
# short transaction, so they can run while the server is up.
namespace :compliance_summaries do
  desc "Recount every host's compliance summary from its rows, creating any that are missing"
  task rebuild: :environment do
    count = HostComplianceSummary.rebuild!
    puts "Rebuilt the compliance summaries of #{count} #{'host'.pluralize(count)}."
  end

  desc "Compare every host's compliance summary with a fresh count of its rows; exits 1 if any differs"
  task check: :environment do
    drifted = HostComplianceSummary.drift
    queued = HostComplianceSummary.queued
    puts "#{queued} #{'host'.pluralize(queued)} queued for a recount after an advisory import (not checked)." if queued.positive?
    if drifted.empty?
      puts "Every host's compliance summary matches its rows."
    else
      abort "#{drifted.size} #{'host'.pluralize(drifted.size)} differ from their rows (host ids #{drifted.first(20).join(', ')}" \
            "#{', ...' if drifted.size > 20}). Run bin/rails compliance_summaries:rebuild."
    end
  end

  # The upgrade steps of migrations 20261120256002 (#256) and 20261123262002 (#262) on a large database
  # (docs/operations/upgrades.md): resumable.
  recount_after_upgrade = lambda do |table|
    $stdout.sync = true # progress as it goes, also into a log file
    recount = ComplianceFixRecount.new(table:, log: ->(message) { puts message })
    next puts("Nothing to recount: the upgrade's recount is finished.") unless recount.needed?

    estimate = recount.estimate
    puts "To recount: #{estimate.hosts} hosts with #{estimate.findings} open findings, about #{(estimate.seconds / 60).ceil} min at the estimate's rates."
    recount.run!
    puts "Done. Start the server again: its migrations finish the upgrade."
  end

  desc "Recount every host's vulnerability fix counts after the upgrade that added them (resumable); then restart the server"
  task recount_fixes: :environment do
    recount_after_upgrade.call(ComplianceFixRecount::TABLE)
  end

  desc "Write the findings' listeners, then recount every host's exposure tier, points, and work after the upgrade that added them (resumable); then restart the server"
  task recount_scores: :environment do
    # The findings' listeners first, so no host is counted without its listener points (review of #305, S2); only while
    # the recount has not started, so only in the upgrade step, with the server down (re-check of #305, S1).
    $stdout.sync = true
    ListenerBackfill.new(recount: ComplianceFixRecount.new(table: "compliance_score_recounts"), log: ->(message) { puts message }).run!
    recount_after_upgrade.call("compliance_score_recounts")
  end
end
