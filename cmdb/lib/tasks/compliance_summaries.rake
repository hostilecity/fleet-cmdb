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

  # The upgrade step of migration 20261120256002 on a large database (#256, docs/operations/upgrades.md): resumable.
  desc "Recount every host's vulnerability fix counts after the upgrade that added them (resumable); then restart the server"
  task recount_fixes: :environment do
    $stdout.sync = true # progress as it goes, also into a log file
    recount = ComplianceFixRecount.new(log: ->(message) { puts message })
    next puts("Nothing to recount: the upgrade's recount is finished.") unless recount.needed?

    estimate = recount.estimate
    puts "To recount: #{estimate.hosts} hosts with #{estimate.findings} open findings, about #{(estimate.seconds / 60).ceil} min at the estimate's rates."
    recount.run!
    puts "Done. Start the server again: its migrations finish the upgrade."
  end
end
