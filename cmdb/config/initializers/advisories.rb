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

  config.after_initialize do
    url = Rails.configuration.x.advisories.feed_url
    raise "FLEET_ADVISORY_FEED_URL must be an https:// URL" if url && !URI.parse(url).is_a?(URI::HTTPS)
  rescue URI::InvalidURIError
    raise "FLEET_ADVISORY_FEED_URL must be an https:// URL"
  end
end
