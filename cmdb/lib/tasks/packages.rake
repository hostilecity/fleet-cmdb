namespace :packages do
  desc "Check the package store's references (ADR 0028): snapshots and hosts with no set, and ids that name nothing"
  task check_snapshots: :environment do
    problems = PackageStore.check
    problems.each { |problem| puts problem }
    puts problems.empty? ? "Package store: every reference is sound." : "Package store: #{problems.size} problems."
    exit 1 if problems.any?
  end
end
