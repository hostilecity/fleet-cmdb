# Operator-adjustable settings, typed with defaults (P1-S09). Only keys defined in DEFINITIONS exist. Change
# them through the methods here so values are validated and every change is audited.
class Setting < ApplicationRecord
  # field: :online, :stale, or nil when the pair is wrong together, so a form can mark the right input.
  class Invalid < StandardError
    attr_reader :field

    def initialize(message, field: nil)
      super(message)
      @field = field
    end
  end

  DEFINITIONS = {
    "liveness.online_threshold_minutes" => { default: 3, range: 1..1_440 },
    "liveness.stale_threshold_minutes" => { default: 15, range: 2..10_080 },
    # The intervals the server asks agents to use (directives.intervals, ADR 0019). Unset by default: agents
    # then keep their configured intervals. The agent clamps them to its own bounds as well.
    "agent.heartbeat_seconds" => { default: nil, range: 10..3_600 },
    "agent.inventory_seconds" => { default: nil, range: 60..86_400 },
    # How long inventory snapshots, recent report ids, and host status events are kept (DEC-07, P1-S10).
    "retention.days" => { default: 90, range: 7..3_650 },
    # Task limits (P3-S06, owner decision Q33). Read and changed only through TaskSettings, which needs the second
    # factor and audits every change. The batch cap can be lowered, never raised past 25 (DEC-14).
    "tasks.max_hosts_per_batch" => { default: 25, range: 1..25 },
    "tasks.output_limit_kib" => { default: 64, range: 4..1_024 },
    "tasks.poll_seconds" => { default: 30, range: 10..300 },
    # { task type => hours } for the types whose expiry was changed; the others keep the catalog's (24 hours).
    "tasks.expiry_hours" => { default: {}.freeze, range: 1..168 }
  }.freeze

  AGENT_INTERVAL_KEYS = { heartbeat_seconds: "agent.heartbeat_seconds", inventory_seconds: "agent.inventory_seconds" }.freeze

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
    raise Invalid.new("Enter a whole number of minutes.", field: :online) if online.nil?
    raise Invalid.new("Enter a whole number of minutes.", field: :stale) if stale.nil?
    raise Invalid.new("Must be shorter than the stale threshold (#{stale} minutes).", field: :online) unless online < stale

    transaction(requires_new: true) do
      write!("liveness.online_threshold_minutes", online, actor:)
      write!("liveness.stale_threshold_minutes", stale, actor:)
    end
  end

  # The retention window for snapshots, report ids, and status events (DEC-07).
  def self.retention_window = get("retention.days").days

  # Sets the retention window in days, audited. Audit entries are not covered: they are never pruned (DEC-07).
  def self.update_retention_days!(days, actor:)
    value = whole_number(days)
    range = DEFINITIONS.fetch("retention.days")[:range]
    raise Invalid.new("Enter a whole number of days from #{range.min} to #{range.max}.") unless value && range.cover?(value)

    transaction(requires_new: true) do
      setting = lock.find_or_initialize_by(key: "retention.days")
      before = setting.persisted? ? setting.value : DEFINITIONS["retention.days"][:default]
      next if before == value

      setting.update!(value:)
      Audit.record(actor:, action: Audit::Actions::SETTING_CHANGED, target: setting, changes: { "retention.days" => [ before, value ] })
    end
  end

  # The intervals to send agents, one SELECT: { heartbeat_seconds: 120 }, with only the ones that are set. Read on
  # every heartbeat.
  def self.agent_intervals
    stored = where(key: AGENT_INTERVAL_KEYS.values).pluck(:key, :value).to_h
    AGENT_INTERVAL_KEYS.filter_map { |name, key| [ name, stored[key] ] if stored.key?(key) }.to_h
  end

  # Sets or clears (nil or blank) the intervals sent to agents, audited. A name that is not passed is left alone.
  def self.update_agent_intervals!(actor:, **intervals)
    unknown = intervals.keys - AGENT_INTERVAL_KEYS.keys
    raise ArgumentError, "unknown interval #{unknown.first}" if unknown.any?

    transaction(requires_new: true) { intervals.each { |name, value| write_interval!(name, value, actor:) } }
  end

  def self.write_interval!(name, value, actor:)
    key = AGENT_INTERVAL_KEYS.fetch(name)
    clear = value.to_s.strip.empty?
    seconds = clear ? nil : whole_number(value)
    range = DEFINITIONS.fetch(key)[:range]
    raise Invalid.new("Enter a whole number of seconds from #{range.min} to #{range.max}.", field: name) unless clear || (seconds && range.cover?(seconds))

    setting = lock.find_or_initialize_by(key:)
    before = setting.persisted? ? setting.value : nil
    return if before == seconds

    seconds.nil? ? setting.destroy! : setting.update!(value: seconds)
    Audit.record(actor:, action: Audit::Actions::SETTING_CHANGED, target: setting, changes: { key => [ before, seconds ] })
  end
  private_class_method :write_interval!

  # An Integer, or a string of digits (from a form or the command line); anything else is nil.
  def self.whole_number(value)
    return value if value.is_a?(Integer)

    value.to_s.strip.match?(/\A\d+\z/) ? value.to_s.to_i : nil
  end
  private_class_method :whole_number

  def self.write!(key, value, actor:)
    range = DEFINITIONS.fetch(key)[:range]
    field = key.include?("online") ? :online : :stale
    raise Invalid.new("Must be between #{range.min} and #{range.max} minutes.", field:) unless range.cover?(value)

    setting = lock.find_or_initialize_by(key:)
    before = setting.persisted? ? setting.value : DEFINITIONS[key][:default]
    return setting if setting.persisted? && before == value

    setting.update!(value:)
    Audit.record(actor:, action: Audit::Actions::SETTING_CHANGED, target: setting, changes: { key => [ before, value ] })
    setting
  end
  private_class_method :write!
end
