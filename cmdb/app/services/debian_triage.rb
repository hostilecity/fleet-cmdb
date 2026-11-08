# The Debian Security Tracker's triage beside each finding (P2-DEBIAN-TRIAGE, FR-2.4, FR-2.5, ADR 0022): a second
# advisory data source beside OSV, imported on the same schedule, that annotates findings and never changes
# their state, severity, or counts.
#
# - DebianTriage::Releases maps a host's inventory to the tracker's release name (config/triage_releases.yml).
# - DebianTriage::Reader reads the tracker's one JSON document one source package at a time, in bounded memory.
# - DebianTriage::Import stores the entries of the releases active hosts report, each release replaced in one
#   transaction, behind a truncation guard, and audits the import.
# - DebianTriageRefreshJob downloads the document with Advisories::Feed on a schedule.
# - DebianTriage::Freshness says how old each release's data is; FindingTriage joins findings to it.
module DebianTriage
  TRACKER = "debian".freeze

  module_function

  def config = Rails.configuration.x.debian_triage

  # The tracker's page for a CVE, for the views (P2-D08): built only from a validated CVE id.
  def tracker_url_for(cve_id) = (cve_id.to_s.match?(Releases::CVE) ? "https://security-tracker.debian.org/tracker/#{cve_id}" : nil)

  def feed
    Advisories::Feed.new(url: config.tracker_url, token: nil, max_bytes: config.max_download_bytes, label: "Debian Security Tracker",
                         accept: "application/json", suffix: ".json")
  end
end
