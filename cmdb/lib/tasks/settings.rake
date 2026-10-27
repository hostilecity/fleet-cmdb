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
end
