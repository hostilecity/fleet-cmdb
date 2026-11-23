# Settings an operator can change before the dashboard settings page exists (P1-S09). Changes are audited
# with the system actor.
namespace :settings do
  desc "Show the current settings"
  task show: :environment do
    Setting::DEFINITIONS.each_key { |key| puts "#{key} = #{Setting.get(key)}" }
  end

  desc "Set the liveness thresholds in minutes: ONLINE_MINUTES=3 STALE_MINUTES=15"
  task liveness: :environment do
    Setting.update_liveness_thresholds!(online_minutes: ENV.fetch("ONLINE_MINUTES"), stale_minutes: ENV.fetch("STALE_MINUTES"), actor: Audit::SYSTEM)
    thresholds = Setting.liveness_thresholds
    puts "Online under #{thresholds[:online].in_minutes.to_i} minutes, stale under #{thresholds[:stale].in_minutes.to_i}, offline after that."
  rescue KeyError
    abort "Usage: bin/rails settings:liveness ONLINE_MINUTES=3 STALE_MINUTES=15"
  rescue Setting::Invalid => e
    abort "Not changed: #{e.message}"
  end

  desc "Set how many days snapshots, report ids, and status events are kept: DAYS=90"
  task retention: :environment do
    Setting.update_retention_days!(ENV.fetch("DAYS"), actor: Audit::SYSTEM)
    puts "Snapshots and status events are kept for at least #{Setting.get('retention.days')} days, report ids for at least 7. Audit entries are never pruned."
  rescue KeyError
    abort "Usage: bin/rails settings:retention DAYS=90"
  rescue Setting::Invalid => e
    abort "Not changed: #{e.message}"
  end

  desc "Set the vulnerability badge settings in days: REPORT_DAYS=3 (package report age) GRACE_DAYS=7 (a run's grace); either may be left out"
  task vulnerability_badges: :environment do
    days = { report_max_age: ENV["REPORT_DAYS"], run_grace: ENV["GRACE_DAYS"] }.compact
    abort "Usage: bin/rails settings:vulnerability_badges REPORT_DAYS=3 GRACE_DAYS=7" if days.empty?

    Setting.update_vulnerability_badges!(actor: Audit::SYSTEM, **days)
    badges = Setting.vulnerability_badges
    puts "Badges and runs are withheld when the last package report is older than #{badges[:report_max_age].in_days.to_i} days; " \
         "a run is kept through a new fixable critical for #{badges[:run_grace].in_days.to_i} days."
  rescue Setting::Invalid => e
    abort "Not changed: #{e.message}"
  end
end
