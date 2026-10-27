# Operator-adjustable settings, typed with defaults (P1-S09). Only keys defined in DEFINITIONS exist. Change
# them through the methods here so values are validated and every change is audited.
class Setting < ApplicationRecord
  class Invalid < StandardError; end

  DEFINITIONS = {
    "liveness.online_threshold_minutes" => { default: 3, range: 1..1_440 },
    "liveness.stale_threshold_minutes" => { default: 15, range: 2..10_080 }
  }.freeze

  validates :key, inclusion: { in: DEFINITIONS.keys }

  def self.get(key)
    definition = DEFINITIONS.fetch(key)
    find_by(key:)&.value || definition[:default]
  end

  # FR-1.4: online if the last heartbeat is newer than online_threshold, stale until stale_threshold,
  # offline after. Read on every evaluation, so a change takes effect on the next run.
  # Both values come from one SELECT, so an evaluation never mixes an old and a new pair (review of #50).
  def self.liveness_thresholds
    keys = %w[liveness.online_threshold_minutes liveness.stale_threshold_minutes]
    stored = where(key: keys).pluck(:key, :value).to_h
    online, stale = keys.map { |key| stored.fetch(key) { DEFINITIONS[key][:default] } }
    { online: online.minutes, stale: stale.minutes }
  end

  def self.update_liveness_thresholds!(online_minutes:, stale_minutes:, actor:)
    online = whole_number(online_minutes)
    stale = whole_number(stale_minutes)
    raise Invalid, "thresholds must be whole numbers of minutes" if online.nil? || stale.nil?
    raise Invalid, "the online threshold must be shorter than the stale threshold" unless online < stale

    transaction(requires_new: true) do
      write!("liveness.online_threshold_minutes", online, actor:)
      write!("liveness.stale_threshold_minutes", stale, actor:)
    end
  end

  # An Integer, or a string of digits (from a form or the command line); anything else is nil.
  def self.whole_number(value)
    return value if value.is_a?(Integer)

    value.to_s.strip.match?(/\A\d+\z/) ? value.to_s.to_i : nil
  end
  private_class_method :whole_number

  def self.write!(key, value, actor:)
    range = DEFINITIONS.fetch(key)[:range]
    raise Invalid, "#{key} must be between #{range.min} and #{range.max}" unless range.cover?(value)

    setting = lock.find_or_initialize_by(key:)
    before = setting.persisted? ? setting.value : DEFINITIONS[key][:default]
    return setting if setting.persisted? && before == value

    setting.update!(value:)
    Audit.record(actor:, action: Audit::Actions::SETTING_CHANGED, target: setting, changes: { key => [ before, value ] })
    setting
  end
  private_class_method :write!
end
