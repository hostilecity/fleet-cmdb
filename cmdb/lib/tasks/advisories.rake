# Advisory data (P2-VULNS, DEC-11): import OSV files by hand, run the scheduled refresh now, and show how
# fresh the data is. Imports are audited with the system actor.
namespace :advisories do
  # FILE, not PATH: shells use PATH.
  desc "Import OSV advisories from a .json file, a directory of them, or a .zip archive: FILE=... [FULL=1 for a complete data set]"
  task import: :environment do
    path = ENV["FILE"].presence or abort "Usage: bin/rails advisories:import FILE=path/to/all.zip [FULL=1]"
    full = ENV["FULL"] == "1"
    source = File.basename(path)
    begin
      result = Advisories::Import.new(origin: "file", source:, full:).call(Advisories::Reader.new(path))
    rescue Advisories::Unreadable => e
      Advisories::Import.record_failure(origin: "file", source:, full:, reason: e.message)
      abort "Nothing imported: #{e.message}"
    end
    AdvisoriesTask.print(result.import)
  end

  desc "Refresh advisory data from the configured feed now (FLEET_ADVISORY_FEED_URL)"
  # Runs once, without the job's retries; a failure is recorded and audited as the job's last attempt would be.
  task refresh: :environment do
    job = AdvisoryFeedRefreshJob.new
    begin
      result = job.perform(kind: "task") # not limited by the manual refresh cool-down, but starts it (P2-S15)
    rescue StandardError => e
      import = job.give_up(e)
      abort "Refresh failed: #{import.reason}"
    end
    result ? AdvisoriesTask.print(result.import) : puts("No feed is configured (FLEET_ADVISORY_FEED_URL is empty).")
  end

  desc "Show how fresh each ecosystem's advisory data is"
  task status: :environment do
    max_age = Advisories.config.max_age
    Advisories::Freshness.statuses.each do |status|
      updated = status.never? ? "never refreshed" : "last updated #{status.updated_at.utc.iso8601}"
      puts "#{status.ecosystem}: #{updated}#{' (older than ' + (max_age / 1.hour).round.to_s + ' hours)' if status.stale}, " \
           "#{AdvisoryPackage.where(ecosystem: status.ecosystem).distinct.count(:advisory_id)} advisories"
    end
    last = AdvisoryImport.order(finished_at: :desc, id: :desc).first
    puts "Last import: #{last.state} #{last.finished_at.utc.iso8601} from #{last.source}#{": #{last.reason}" if last.reason}" if last
  end
end

module AdvisoriesTask
  module_function

  def print(import)
    counts = import.counts
    return puts("#{import.source}: not modified since the last refresh.") if counts["not_modified"]

    puts "#{import.source}: #{counts['records']} records, #{counts['created']} added, #{counts['updated']} updated, " \
         "#{counts['unchanged']} unchanged, #{counts['older']} older than stored, #{counts['skipped']} for other ecosystems, " \
         "#{counts['withdrawn'] + counts['absent']} withdrawn, #{counts['malformed']} malformed."
    puts "#{counts['rejected_urls']} reference URLs were not http or https and were dropped." if counts["rejected_urls"].positive?
    import.problems.each { |p| puts "  malformed: #{p['location']}#{" (#{p['id']})" if p['id']} #{p['problem']}" }
    puts "  (only the first #{Advisories::Import::PROBLEM_LIMIT} are listed)" if counts["malformed"] > import.problems.size
  end
end

namespace :vulnerabilities do
  desc "Match every host in the fleet against the advisory data now (normally done after each package report and import)"
  task match: :environment do
    outcome = VulnerabilityMatcher.match!(Host.in_fleet.pluck(:id))
    puts "#{outcome.evaluated} hosts evaluated, #{outcome.not_evaluated} not evaluated; " \
         "#{outcome.opened} findings opened, #{outcome.reopened} reopened, #{outcome.resolved} resolved."
  end
end
