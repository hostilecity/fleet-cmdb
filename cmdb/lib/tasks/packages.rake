namespace :packages do
  desc "Move an upgraded database's package lists into package sets (#196, ADR 0028; docs/operations/upgrades.md); resumable"
  task backfill: :environment do
    $stdout.sync = true # progress as it goes, also into a log file
    backfill = PackageStoreBackfill.new(log: ->(message) { puts message })
    puts "To move: #{backfill.pending.map { |what, count| "#{count} #{what.tr('_', ' ')}" }.join(', ')}."
    begin
      backfill.run!
    rescue PackageStoreBackfill::Busy => e
      abort e.message
    end
    puts "Done. Start the server again: its migrations finish the upgrade."
  end

  desc "Check the package store's references (ADR 0028): snapshots and hosts with no set, and ids that name nothing"
  task check_snapshots: :environment do
    problems = PackageStore.check
    problems.each { |problem| puts problem }
    puts problems.empty? ? "Package store: every reference is sound." : "Package store: #{problems.size} problems."
    exit 1 if problems.any?
  end
end
