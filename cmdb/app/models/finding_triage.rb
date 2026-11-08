# Debian's triage beside a page of vulnerability findings (P2-S16, ADR 0022), for the host's vulnerabilities tab and
# the package page (P2-D08). Loaded for the whole page in a fixed number of queries, whatever its size: the
# findings' advisories (none when already loaded), the hosts' inventories, freshness, and one query for the
# triage entries. Nothing here changes a finding: it only reads.
#
# A finding is joined to triage_entries by its source package, its host's release (DebianTriage::Releases, from
# the host's inventory), and its advisory's CVE ids (FindingTriage.cve_ids). When there is none to show, the
# reason says why, and the views say Debian's triage is not available rather than implying Debian has no view:
#
#   triage = FindingTriage.load(findings)
#   t = triage[finding]   # FindingTriage::Triage
#   t.available?          # entries to show
#   t.entries             # [TriageEntry], one per CVE the tracker has for it, by CVE id
#   t.reason, t.detail    # why not: "stale", and a sentence to show
class FindingTriage
  REASONS = {
    "unmapped_release" => "%s has no release in the Debian Security Tracker's release table.",
    "source_off" => "Debian triage is turned off (FLEET_DEBIAN_TRACKER_URL is empty) and no current data has been imported for %s.",
    "never_imported" => "Debian triage for %s has not been imported yet; it is imported at the next refresh once an active host reports that release.",
    "stale" => "Debian triage for %s is older than %d hours.",
    "no_cve" => "The advisory names no CVE to look up in the Debian Security Tracker.",
    "no_entry" => "The Debian Security Tracker has no entry for this package and CVE in %s."
  }.freeze

  # release: the host's release, or nil. cve_ids: the advisory's CVE ids. entries: the triage found (empty unless
  # available). reason: nil, or a key of REASONS; detail: its sentence.
  Triage = Data.define(:release, :cve_ids, :entries, :reason, :detail) do
    def available? = reason.nil?
  end

  # The CVE ids an advisory's triage is looked up by: its own id for a DEBIAN-CVE-* record, and its aliases and
  # upstream ids (stored together as aliases) for DSA-* and DLA-* records.
  def self.cve_ids(advisory)
    [ advisory.advisory_id.delete_prefix("DEBIAN-"), *advisory.aliases ].grep(DebianTriage::Releases::CVE).uniq.sort
  end

  # findings: VulnerabilityFinding records (a relation or an array).
  def self.load(findings, now: Time.current, max_age: Advisories.config.max_age) = new(findings.to_a, now:, max_age:)

  def initialize(findings, now:, max_age:)
    @max_age = max_age
    ActiveRecord::Associations::Preloader.new(records: findings.reject { |f| f.association(:advisory).loaded? }, associations: :advisory).call
    os = HostInventory.where(host_id: findings.map(&:host_id).uniq).pluck(:host_id, Arel.sql("stable -> 'os'")).to_h
    @hosts = os.transform_values { |value| [ DebianTriage::Releases.for_os(value), value ] }
    @freshness = DebianTriage::Freshness.statuses(now:, max_age:).index_by(&:release)
    @url = DebianTriage.config.tracker_url
    looked_up = findings.select { |finding| unavailable_reason(finding).nil? }
    @entries = entries_for(looked_up)
    @triage = findings.to_h { |finding| [ finding.id, build(finding) ] }
  end

  def [](finding) = @triage.fetch(finding.id)

  private

  def release_of(finding) = @hosts.dig(finding.host_id, 0)

  # Why a finding cannot have triage before the entries are looked at, or nil.
  def unavailable_reason(finding)
    release = release_of(finding)
    status = @freshness[release]
    if release.nil? then [ "unmapped_release", os_name(@hosts.dig(finding.host_id, 1)) ]
    elsif status.stale && @url.nil? then [ "source_off", release ]
    elsif status.never? then [ "never_imported", release ]
    elsif status.stale then [ "stale", release, (@max_age / 1.hour).round ]
    elsif self.class.cve_ids(finding.advisory).empty? then [ "no_cve" ]
    end
  end

  def entries_for(findings)
    return {} if findings.empty?

    TriageEntry.where(tracker: DebianTriage::TRACKER, release: findings.map { |f| release_of(f) }.uniq, package: findings.map(&:source).uniq,
                      cve_id: findings.flat_map { |f| self.class.cve_ids(f.advisory) }.uniq)
               .index_by { |entry| [ entry.release, entry.package, entry.cve_id ] }
  end

  def build(finding)
    release = release_of(finding)
    cve_ids = self.class.cve_ids(finding.advisory)
    reason = unavailable_reason(finding)
    # In cve_ids' order (sorted in Ruby, so the database's collation does not decide it).
    entries = reason ? [] : cve_ids.filter_map { |cve_id| @entries[[ release, finding.source, cve_id ]] }
    reason ||= [ "no_entry", release ] if entries.empty?
    key, *arguments = reason
    Triage.new(release:, cve_ids:, entries:, reason: key, detail: key && format(REASONS.fetch(key), *arguments))
  end

  def os_name(os)
    return "The host's distribution" unless os.is_a?(Hash)

    [ os["id"], os["version_id"] ].compact.join(" ").presence || "The host's distribution"
  end
end
