# The Debian Security Tracker's triage beside each finding (P2-S16, ADR 0022). Environment files may set any of
# these first; tests do. Staleness uses FLEET_ADVISORY_MAX_AGE_HOURS and the truncation guard
# FLEET_ADVISORY_WITHDRAW_SHARE, as for OSV (config/initializers/advisories.rb).
Rails.application.configure do
  triage = config.x.debian_triage

  # The one JSON document the scheduled refresh downloads. HTTPS only. Set it empty to turn the refresh off (a
  # server without internet access imports the file with bin/rails advisories:triage_import instead).
  triage.tracker_url = ENV.fetch("FLEET_DEBIAN_TRACKER_URL", "https://security-tracker.debian.org/tracker/data/json").presence unless triage.key?(:tracker_url)

  # The largest document downloaded or imported, in MB. Measured on 2026-11-07 at 84.2 MiB (cmdb/README.md).
  triage.max_download_bytes ||= begin
    value = ENV["FLEET_DEBIAN_TRACKER_MAX_DOWNLOAD_MB"].presence || "512"
    megabytes = Integer(value, 10, exception: false)
    raise "FLEET_DEBIAN_TRACKER_MAX_DOWNLOAD_MB must be a whole number of megabytes, at least 1 (got #{value.inspect})" unless megabytes&.positive?

    megabytes.megabytes
  end

  # The release table (config/triage_releases.yml): { ["debian", "13"] => "trixie", ["debian", nil] => "sid" }.
  # Checked here, so a mistake stops the server from starting rather than importing nothing.
  triage.releases ||= begin
    file = Rails.root.join("config/triage_releases.yml")
    rows = YAML.safe_load_file(file)&.fetch("debian", nil)
    raise "#{file}: debian must be a list of { id, version_id, release }" unless rows.is_a?(Array) && rows.any?

    rows.each_with_object({}) do |row, table|
      id, version_id, release = row.is_a?(Hash) ? row.values_at("id", "version_id", "release") : []
      unless id.is_a?(String) && id.match?(/\A[a-z0-9._-]{1,64}\z/) && (version_id.nil? || version_id.is_a?(String)) &&
             release.is_a?(String) && release.match?(/\A[a-z][a-z0-9-]{0,31}\z/)
        raise "#{file}: #{row.inspect} must have an id, a version_id (a string, or null), and a release name"
      end
      raise "#{file}: #{id} #{version_id.inspect} is listed twice" if table.key?([ id, version_id ])

      table[[ id, version_id ]] = release
    end.freeze
  end

  config.after_initialize do
    url = Rails.configuration.x.debian_triage.tracker_url
    raise "FLEET_DEBIAN_TRACKER_URL must be an https:// URL" if url && !URI.parse(url).is_a?(URI::HTTPS)
  rescue URI::InvalidURIError
    raise "FLEET_DEBIAN_TRACKER_URL must be an https:// URL"
  end
end
