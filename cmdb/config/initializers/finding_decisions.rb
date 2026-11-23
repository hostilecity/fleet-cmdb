# Operator decisions on findings (VT-OVERRIDES #261, epic decision 15): the longest a control or an accepted risk may
# last, in days, and the shorter limit for an advisory on CISA's KEV list. Environment files may set them first; tests
# do. A malformed value stops the server from starting, naming the setting.
Rails.application.configure do
  decisions = config.x.finding_decisions
  days = lambda do |name, default|
    value = ENV[name].presence || default
    number = Integer(value, 10, exception: false)
    raise "#{name} must be a whole number of days from 1 to 366 (got #{value.inspect})" unless number&.between?(1, 366)

    number
  end
  decisions.max_days ||= days.call("FLEET_DECISION_MAX_DAYS", "90")
  decisions.max_days_kev ||= days.call("FLEET_DECISION_MAX_DAYS_KEV", "30")
  raise "FLEET_DECISION_MAX_DAYS_KEV (#{decisions.max_days_kev}) must not be above FLEET_DECISION_MAX_DAYS (#{decisions.max_days})" if decisions.max_days_kev > decisions.max_days
end

# Rule O1's controls (VT-OVERRIDES #261): VulnerabilityTriage::HostFacts reads the active, unexpired controls through
# this source. Set again on every reload in development.
Rails.application.config.to_prepare do
  VulnerabilityTriage::HostFacts.control_source = FindingDecisions::ControlSource
end
