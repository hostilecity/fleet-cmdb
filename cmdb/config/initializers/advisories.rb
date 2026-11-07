# Vulnerability advisory data (P2-VULNS, DEC-11). Environment files may set any of these first; tests do.
Rails.application.configure do
  advisories = config.x.advisories

  # The scheduled refresh downloads this OSV archive (P2-S13). OSV publishes one all.zip per ecosystem without
  # its release suffix, so Debian's covers every release; the importer keeps only the fleet profile's
  # (Ecosystems). HTTPS only. Set it empty to turn the refresh off (a server without internet access imports
  # files by hand instead).
  advisories.feed_url = ENV.fetch("FLEET_ADVISORY_FEED_URL", "https://storage.googleapis.com/osv-vulnerabilities/Debian/all.zip").presence unless advisories.key?(:feed_url)

  # Sent as "Authorization: Bearer ..." when set, for a mirror that needs one. Never logged or shown: errors
  # name only the feed's host.
  advisories.feed_token ||= Rails.application.credentials.dig(:advisories, :feed_token) || ENV["FLEET_ADVISORY_FEED_TOKEN"].presence

  # The largest download accepted.
  advisories.max_download_bytes ||= Integer(ENV.fetch("FLEET_ADVISORY_MAX_DOWNLOAD_MB", "512")).megabytes

  # Data older than this shows a warning on the dashboard (P2-S13).
  advisories.max_age ||= Float(ENV.fetch("FLEET_ADVISORY_MAX_AGE_HOURS", "48")).hours

  # The cool-down on the dashboard's "Refresh now" (P2-S15), in seconds: a manual refresh is refused while the
  # last refresh of any kind started less than this long ago. A whole number, at least 1; anything else stops
  # the server from starting, rather than silently allowing refreshes back to back.
  advisories.refresh_cooldown ||= begin
    value = ENV["FLEET_ADVISORY_REFRESH_COOLDOWN"].presence || "300"
    seconds = Integer(value, 10, exception: false)
    raise "FLEET_ADVISORY_REFRESH_COOLDOWN must be a whole number of seconds, at least 1 (got #{value.inspect})" unless seconds&.positive?

    seconds.seconds
  end

  # The withdrawal guard on every full import (P2-S10, P2-S13, review of #129): a full import that would mark
  # more than this share of an ecosystem's current advisories withdrawn, or any of them when it has fewer than
  # FLEET_ADVISORY_WITHDRAW_MIN_RECORDS records for that ecosystem, is refused with the counts until an operator
  # allows them. The same rule for every ecosystem. A share is a decimal from 0 to 1 and the floor a whole number
  # from 0; anything else stops the server from starting.
  advisories.withdraw_share ||= begin
    value = ENV["FLEET_ADVISORY_WITHDRAW_SHARE"].presence || "0.10"
    share = Float(value, exception: false)
    raise "FLEET_ADVISORY_WITHDRAW_SHARE must be a decimal from 0 to 1 (got #{value.inspect})" unless share&.between?(0, 1)

    share
  end
  advisories.withdraw_min_records ||= begin
    value = ENV["FLEET_ADVISORY_WITHDRAW_MIN_RECORDS"].presence || "1000"
    records = Integer(value, 10, exception: false)
    raise "FLEET_ADVISORY_WITHDRAW_MIN_RECORDS must be a whole number, 0 or more (got #{value.inspect})" unless records && records >= 0

    records
  end

  config.after_initialize do
    url = Rails.configuration.x.advisories.feed_url
    raise "FLEET_ADVISORY_FEED_URL must be an https:// URL" if url && !URI.parse(url).is_a?(URI::HTTPS)
  rescue URI::InvalidURIError
    raise "FLEET_ADVISORY_FEED_URL must be an https:// URL"
  end
end
