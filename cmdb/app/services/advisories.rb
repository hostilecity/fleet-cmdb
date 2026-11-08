# Vulnerability advisories (P2-VULNS, FR-2.4, DEC-11): OSV records for the fleet profile's ecosystems
# (Ecosystems), imported from a file, a directory, or an archive, or downloaded on a schedule.
#
# - Advisories::Reader yields the JSON documents in a file, directory, or zip archive, within size limits.
# - Advisories::Record validates and cleans one OSV record; Advisories::Severity normalises its severity.
# - Advisories::Import stores records idempotently and audits the import.
# - Advisories::Feed downloads the configured archive; AdvisoryFeedRefreshJob runs it on a schedule.
# - Advisories::Freshness says how old each ecosystem's data is (P2-S13).
module Advisories
  # The input cannot be imported at all (an unreadable archive, a missing path, too much data). Nothing is
  # written. The message is fixed text plus, at most, sizes and the name the operator gave, so it is safe to
  # show and to audit.
  class Unreadable < StandardError; end

  module_function

  def config = Rails.configuration.x.advisories
end
