# Exploitation signals (VT-SIGNALS, FR-2.6, ADR 0032 point 5): CISA's Known Exploited Vulnerabilities catalog and
# FIRST's EPSS scores, fetched by the server only. Environment files may set any of these first; tests do. The
# truncation guard uses FLEET_ADVISORY_WITHDRAW_SHARE, as the other sources do (config/initializers/advisories.rb).
# A malformed value stops the server from starting, naming the setting.
Rails.application.configure do
  signals = config.x.signals

  # CISA KEV's JSON catalog, every 6 hours after the advisory refresh. CISA's GitHub mirror by default (CC0, synced
  # shortly after cisa.gov); CISA's own https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  # is the alternative. HTTPS only, and no redirect to another host. Empty turns the refresh off and keeps the last data.
  signals.kev_url = ENV.fetch("FLEET_KEV_URL", "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json").presence unless signals.key?(:kev_url)

  signals.kev_max_download_bytes ||= begin
    value = ENV["FLEET_KEV_MAX_DOWNLOAD_MB"].presence || "16"
    megabytes = Integer(value, 10, exception: false)
    raise "FLEET_KEV_MAX_DOWNLOAD_MB must be a whole number of megabytes, at least 1 (got #{value.inspect})" unless megabytes&.positive?

    megabytes.megabytes
  end

  # FIRST EPSS's daily gzip CSV, at 14:30 UTC. Empty turns the refresh off and keeps the last data.
  signals.epss_url = ENV.fetch("FLEET_EPSS_URL", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz").presence unless signals.key?(:epss_url)

  # The hosts EPSS's download may redirect to, besides its own (comma-separated host names). Any other host is refused,
  # so an allowlisted egress needs only these (docs/operations/configuration.md, "Outbound access").
  signals.epss_redirect_hosts ||= begin
    hosts = ENV.fetch("FLEET_EPSS_REDIRECT_HOSTS", "").split(",").map { |host| host.strip.downcase }.compact_blank
    bad = hosts.reject { |host| host.match?(/\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+\z/) }
    raise "FLEET_EPSS_REDIRECT_HOSTS must be host names separated by commas (got #{bad.first.inspect})" if bad.any?

    hosts.freeze
  end

  # The EPSS band's hysteresis (owner decision 6): high from a score of at least ENTER, until it falls below LEAVE.
  share = lambda do |name, default|
    value = ENV[name].presence || default
    number = Float(value, exception: false)
    raise "#{name} must be a decimal from 0 to 1 (got #{value.inspect})" unless number&.between?(0, 1)

    number
  end
  signals.epss_enter ||= share.call("FLEET_EPSS_ENTER", "0.10")
  signals.epss_leave ||= share.call("FLEET_EPSS_LEAVE", "0.07")
  raise "FLEET_EPSS_LEAVE (#{signals.epss_leave}) must not be above FLEET_EPSS_ENTER (#{signals.epss_enter})" if signals.epss_leave > signals.epss_enter

  # KEV and EPSS data older than this is shown as stale (owner decision 7). Stale data is still used (B1).
  signals.max_age ||= begin
    value = ENV["FLEET_SIGNAL_MAX_AGE_HOURS"].presence || "168"
    hours = Integer(value, 10, exception: false)
    raise "FLEET_SIGNAL_MAX_AGE_HOURS must be a whole number of hours, at least 1 (got #{value.inspect})" unless hours&.positive?

    hours.hours
  end

  config.after_initialize do
    { "FLEET_KEV_URL" => Rails.configuration.x.signals.kev_url, "FLEET_EPSS_URL" => Rails.configuration.x.signals.epss_url }.each do |name, url|
      valid = url.nil? || (URI.parse(url).is_a?(URI::HTTPS) rescue false) # rubocop:disable Style/RescueModifier
      raise "#{name} must be an https:// URL" unless valid
    end
  end
end
