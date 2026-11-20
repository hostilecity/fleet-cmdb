# Exploitation signals (VT-SIGNALS, ADR 0032): CISA KEV and FIRST EPSS, refreshed now or imported from a file on a
# server without internet access, and the KEV data cleared. Imports are audited with the system actor.
#
# An import that would drop more than FLEET_ADVISORY_WITHDRAW_SHARE of the stored entries stores nothing and prints the
# counts, until ALLOW_DROPS=<count> confirms them (a ceiling, not a bypass).
namespace :signals do
  desc "Import CISA's Known Exploited Vulnerabilities catalog from a JSON file: FILE=... [ALLOW_DROPS=count]"
  task kev_import: :environment do
    path = ENV["FILE"].presence or abort "Usage: bin/rails signals:kev_import FILE=path/to/known_exploited_vulnerabilities.json [ALLOW_DROPS=12]"
    SignalsTask.import(Signals::KEV, path, "bin/rails signals:kev_import FILE=#{path}") do |source, allowed|
      Signals::KevImport.new(origin: "file", source:, allowed_drops: allowed).call(Signals::KevReader.new(path).read)
    end
  end

  desc "Refresh CISA's Known Exploited Vulnerabilities catalog now (FLEET_KEV_URL) [ALLOW_DROPS=count]"
  task kev_refresh: :environment do
    SignalsTask.refresh(KevRefreshJob.new, Signals::KEV, "FLEET_KEV_URL", "bin/rails signals:kev_refresh")
  end

  desc "Delete the stored KEV entries (rules N1 and I5 stop applying until KEV is imported again): CONFIRM=1"
  task kev_clear: :environment do
    abort "This deletes every stored KEV entry: rule N1 (known exploited) and rule I5 stop applying until KEV is imported again.\n" \
          "Run it again with CONFIRM=1 to go ahead: bin/rails signals:kev_clear CONFIRM=1" unless ENV["CONFIRM"] == "1"

    import = Signals.clear!(Signals::KEV)
    puts "#{import.counts['deleted']} KEV entries deleted. #{import.reason}."
  end

  # The way out of a wrong stored EPSS score date (a file dated in the future, review of #269): a file older than the
  # stored scores is refused, so this deletes them and lets the next file of any date import.
  desc "Delete the stored EPSS scores so the next file imports whatever its date (rule N2 stops applying until then): CONFIRM=1"
  task epss_reset: :environment do
    abort "This deletes every stored EPSS score: rule N2 stops applying until EPSS is imported again.\n" \
          "Run it again with CONFIRM=1 to go ahead: bin/rails signals:epss_reset CONFIRM=1" unless ENV["CONFIRM"] == "1"

    import = Signals.clear!(Signals::EPSS)
    puts "#{import.counts['deleted']} EPSS scores deleted. #{import.reason}."
  end

  # The Data sources panels' "matches open findings" counts are made by a job after each import; this queues them again
  # for the latest imports, after a count that failed or was too slow (reviews of #269).
  desc "Count again how many KEV and high-band EPSS CVEs match open findings (the Data sources panels), in the background"
  task recount: :environment do
    imports = Signals.recount_later
    puts imports.empty? ? "Nothing to count: no KEV or EPSS data is stored." : "Queued: #{imports.map { |i| "#{i.signal.upcase} (import #{i.id})" }.join(', ')}."
  end

  desc "Import FIRST's EPSS scores from a .csv.gz (or .csv) file: FILE=... [ALLOW_DROPS=count]"
  task epss_import: :environment do
    path = ENV["FILE"].presence or abort "Usage: bin/rails signals:epss_import FILE=path/to/epss_scores-current.csv.gz [ALLOW_DROPS=120]"
    SignalsTask.import(Signals::EPSS, path, "bin/rails signals:epss_import FILE=#{path}") do |source, allowed|
      Signals::EpssImport.new(origin: "file", source:, allowed_drops: allowed).call(Signals::EpssReader.new(path))
    end
  end

  desc "Refresh FIRST's EPSS scores now (FLEET_EPSS_URL) [ALLOW_DROPS=count]"
  task epss_refresh: :environment do
    SignalsTask.refresh(EpssRefreshJob.new, Signals::EPSS, "FLEET_EPSS_URL", "bin/rails signals:epss_refresh")
  end
end

module SignalsTask
  module_function

  # ALLOW_DROPS=12 => 12; unset => nil.
  def allowance
    value = ENV["ALLOW_DROPS"].presence or return nil
    abort "ALLOW_DROPS must be a whole number (got #{value.inspect})" unless value.match?(/\A\d+\z/)

    Integer(value, 10)
  end

  def import(signal, path, command)
    source = File.basename(path)
    begin
      import = yield(source, allowance)
    rescue Advisories::Unreadable, Signals::EpssImport::Older => e
      Signals.record_failure(signal, origin: "file", source:, reason: e.message)
      abort "Nothing imported: #{e.message}"
    rescue *Signals::CONNECTION_ERRORS
      Signals.reconnect!
      Signals.record_failure(signal, origin: "file", source:, reason: Signals::CONNECTION_LOST)
      abort "Nothing imported: #{Signals::CONNECTION_LOST}"
    end
    print(import, command)
  end

  # Runs once, without the job's retries; a failure is recorded and audited as the job's last attempt would be.
  def refresh(job, signal, setting, command)
    begin
      import = job.perform(allowed_drops: allowance)
    rescue StandardError => e
      abort "Refresh failed: #{job.give_up(e).reason}"
    end
    return puts("No #{signal.upcase} source is configured (#{setting} is empty).") unless import

    print(import, command)
  end

  def print(import, command)
    return puts("#{import.source}: not modified since the last refresh.") if import.not_modified?
    abort "Nothing imported: #{import.reason}" if import.state == "failed"

    counts = import.counts
    puts "#{import.source} (#{import.version || 'no version'}#{", scores of #{import.score_date.iso8601}" if import.score_date}): " \
         "#{counts.map { |key, value| "#{key.tr('_', ' ')} #{value}" }.join(', ')}"
    import.problems.each { |p| puts "  malformed: #{p.map { |key, value| "#{key} #{value}" }.join(', ')}" }
    return unless import.state == "held_back"

    abort "Held back: #{import.reason}.\nIf that is right, run it again with ALLOW_DROPS=#{counts['removed'] || counts['dropped']} #{command}"
  end
end
