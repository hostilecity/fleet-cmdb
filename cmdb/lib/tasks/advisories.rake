# Advisory data (P2-VULNS, DEC-11): import OSV files by hand, run the scheduled refresh now, and show how
# fresh the data is. Imports are audited with the system actor.
namespace :advisories do
  # FILE, not PATH: shells use PATH.
  # A full import that would withdraw too many advisories is refused with the counts (review of #129), until
  # ALLOW_WITHDRAWALS names them: ALLOW_WITHDRAWALS=Debian:13:41 (ecosystem, colon, count; several separated by commas).
  desc "Import OSV advisories from a .json file, a directory of them, or a .zip archive: FILE=... [FULL=1 for a complete data set] [ALLOW_WITHDRAWALS=ecosystem:count,...]"
  task import: :environment do
    path = ENV["FILE"].presence or abort "Usage: bin/rails advisories:import FILE=path/to/all.zip [FULL=1] [ALLOW_WITHDRAWALS=Debian:13:41]"
    full = ENV["FULL"] == "1"
    allowed = AdvisoriesTask.allowance(ENV["ALLOW_WITHDRAWALS"])
    source = File.basename(path)
    begin
      result = Advisories::Import.new(origin: "file", source:, full:, allowed_withdrawals: allowed).call(Advisories::Reader.new(path))
    rescue Advisories::Unreadable => e
      Advisories::Import.record_failure(origin: "file", source:, full:, reason: e.message)
      abort "Nothing imported: #{e.message}"
    rescue Advisories::Import::WithdrawalsRefused => e
      Advisories::Import.record_held_back(e, origin: "file", source:, full:)
      abort AdvisoriesTask.refusal(e.withdrawals, "bin/rails advisories:import FILE=#{path} FULL=1")
    end
    AdvisoriesTask.print(result.import)
  end

  desc "Refresh advisory data from the configured feed now (FLEET_ADVISORY_FEED_URL)"
  # Runs once, without the job's retries; a failure is recorded and audited as the job's last attempt would be.
  task refresh: :environment do
    job = AdvisoryFeedRefreshJob.new
    allowed = AdvisoriesTask.allowance(ENV["ALLOW_WITHDRAWALS"])
    begin
      result = job.perform(kind: "task", allowed_withdrawals: allowed) # not limited by the manual refresh cool-down, but starts it (P2-S15)
    rescue StandardError => e
      import = job.give_up(e)
      abort "Refresh failed: #{import.reason}"
    end
    next puts("No feed is configured (FLEET_ADVISORY_FEED_URL is empty).") unless result

    if (withdrawals = result.import.counts["would_withdraw"])
      abort AdvisoriesTask.refusal(withdrawals, "bin/rails advisories:refresh")
    end
    AdvisoriesTask.print(result.import)
  end

  # Debian's triage beside each finding (P2-S16, ADR 0022). An import that would drop more than
  # FLEET_ADVISORY_WITHDRAW_SHARE of a release's stored entries keeps that release's data and prints the counts,
  # until ALLOW_DROPS names them: ALLOW_DROPS=trixie:120 (release, colon, count; several separated by commas).
  desc "Import the Debian Security Tracker's JSON document from a file: FILE=... [ALLOW_DROPS=release:count,...]"
  task triage_import: :environment do
    path = ENV["FILE"].presence or abort "Usage: bin/rails advisories:triage_import FILE=path/to/json [ALLOW_DROPS=trixie:120]"
    source = File.basename(path)
    begin
      import = DebianTriage::Import.new(origin: "file", source:, allowed_drops: AdvisoriesTask.allowance(ENV["ALLOW_DROPS"], "ALLOW_DROPS", "trixie:120"))
                                   .call(DebianTriage::Reader.new(path))
    rescue Advisories::Unreadable => e
      DebianTriage::Import.record_failure(origin: "file", source:, reason: e.message)
      abort "Nothing imported: #{e.message}"
    end
    AdvisoriesTask.print_triage(import, "bin/rails advisories:triage_import FILE=#{path}")
  end

  desc "Refresh Debian's triage from the Debian Security Tracker now (FLEET_DEBIAN_TRACKER_URL) [ALLOW_DROPS=release:count,...]"
  # Runs once, without the job's retries; a failure is recorded and audited as the job's last attempt would be.
  task triage_refresh: :environment do
    job = DebianTriageRefreshJob.new
    begin
      import = job.perform(allowed_drops: AdvisoriesTask.allowance(ENV["ALLOW_DROPS"], "ALLOW_DROPS", "trixie:120"))
    rescue StandardError => e
      abort "Refresh failed: #{job.give_up(e).reason}"
    end
    next puts("No Debian Security Tracker is configured (FLEET_DEBIAN_TRACKER_URL is empty).") unless import

    AdvisoriesTask.print_triage(import, "bin/rails advisories:triage_refresh")
  end

  desc "Show how fresh each ecosystem's advisory data and each release's Debian triage is"
  task status: :environment do
    max_age = Advisories.config.max_age
    Advisories::Freshness.statuses.each do |status|
      updated = status.never? ? "never refreshed" : "last updated #{status.updated_at.utc.iso8601}"
      puts "#{status.ecosystem}: #{updated}#{' (older than ' + (max_age / 1.hour).round.to_s + ' hours)' if status.stale}, " \
           "#{AdvisoryPackage.where(ecosystem: status.ecosystem).distinct.count(:advisory_id)} advisories"
    end
    last = AdvisoryImport.finished.order(finished_at: :desc, id: :desc).first
    puts "Last import: #{last.state} #{last.finished_at.utc.iso8601} from #{last.source}#{": #{last.reason}" if last.reason}" if last
    DebianTriage::Freshness.statuses.each do |status|
      updated = status.never? ? "never imported" : "last updated #{status.updated_at.utc.iso8601}"
      puts "Debian triage, #{status.release}: #{updated}#{' (older than ' + (max_age / 1.hour).round.to_s + ' hours)' if status.stale}, " \
           "#{TriageEntry.where(tracker: DebianTriage::TRACKER, release: status.release).count} entries"
    end
  end
end

module AdvisoriesTask
  module_function

  # ALLOW_WITHDRAWALS=Debian:13:41,Other:1:3 => { "Debian:13" => 41, "Other:1" => 3 }. The count follows the last
  # colon, since ecosystem names contain colons.
  # ALLOW_DROPS=trixie:120 => { "trixie" => 120 } in the same way.
  def allowance(value, name = "ALLOW_WITHDRAWALS", example = "Debian:13:41")
    return {} if value.blank?

    value.split(",").to_h do |pair|
      key, _, count = pair.strip.rpartition(":")
      abort "#{name} must be #{name == 'ALLOW_DROPS' ? 'release' : 'ecosystem'}:count pairs separated by commas, such as #{example} (got #{pair.strip.inspect})" unless key.present? && count.match?(/\A\d+\z/)

      [ key, Integer(count, 10) ]
    end
  end

  # A triage import's counts; for one held back, the releases that kept their data and the exact allowance.
  def print_triage(import, command)
    counts = import.counts
    return puts("#{import.source}: not modified since the last refresh.") if counts["not_modified"]

    puts "#{import.source}: #{counts['packages']} source packages, #{counts['entries']} entries (#{counts['other_ids']} not CVE ids), " \
         "#{counts['malformed']} malformed, #{counts['other_releases']} for releases not in the table."
    counts["releases"].each do |release, c|
      puts "  #{release}: #{c['in_file']} entries in the file, #{c['stored']} stored before, #{c['dropped']} dropped, #{c['outcome'].tr('_', ' ')}"
    end
    counts["removed_releases"].each { |release, n| puts "  #{release}: no longer in the release table, #{n} entries deleted" }
    import.problems.each { |p| puts "  malformed: #{p['package']}#{" #{p['id']}" if p['id']} #{p['problem']}" }
    return unless import.state == "held_back"

    held = counts["releases"].select { |_, c| c["outcome"] == "held_back" }
    abort "Held back: #{import.reason}.\nIf that is right, run it again with ALLOW_DROPS=#{held.map { |r, c| "#{r}:#{c['dropped']}" }.join(',')} #{command}"
  end

  # The refusal with the counts, and the command that allows exactly them.
  def refusal(withdrawals, command)
    lines = withdrawals.map { |ecosystem, w| "  #{ecosystem}: #{w['withdraw']} of #{w['current']} current advisories (#{w['records']} records in the import)" }
    allow = withdrawals.map { |ecosystem, w| "#{ecosystem}:#{w['withdraw']}" }.join(",")
    "Nothing imported: this full import would mark advisories withdrawn, which resolves the findings they produced:\n#{lines.join("\n")}\n" \
      "If that is right, run it again with ALLOW_WITHDRAWALS=#{allow} #{command}"
  end

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
