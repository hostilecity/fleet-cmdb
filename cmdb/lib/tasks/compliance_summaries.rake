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
    if drifted.empty?
      puts "Every host's compliance summary matches its rows."
    else
      abort "#{drifted.size} #{'host'.pluralize(drifted.size)} differ from their rows (host ids #{drifted.first(20).join(', ')}" \
            "#{', ...' if drifted.size > 20}). Run bin/rails compliance_summaries:rebuild."
    end
  end
end
