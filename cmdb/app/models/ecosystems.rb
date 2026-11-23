# Which advisory ecosystem a host's distribution belongs to (DEC-01, DEC-11, P2-S11). Advisories are scoped to
# a distribution release ("Debian:13" in OSV), and a host is matched only against its own release's data, from
# the os id and version_id its inventory reports. The table is the fleet profile: adding a distribution or
# release here needs a new decision (DEC-01). The importer keeps only the ecosystems listed here and the ones their
# backports are built from (BACKPORTS).
module Ecosystems
  # [os id, version_id] => OSV ecosystem
  TABLE = { [ "debian", "13" ] => "Debian:13" }.freeze

  # Backports (#274, ADR 0011; the owner chose matching them against the release they are built from on 2026-11-23). A
  # package from the release's backports suite (trixie-backports) is not the release's own: Debian builds it from the
  # next release's version (forky's) with "~bpo<release>+<n>" appended, the security tracker does not cover it for the
  # release, and the release's advisories follow the release's own series (6.12 for trixie's kernel). OSV lists the
  # ~bpo13 builds under Debian:14. A package whose version has the marker is also matched against that ecosystem's
  # advisories, at its own version, once its data is complete here (Backports.data?), and still against its own
  # release's; VulnerabilityMatcher::Chunks.backport_verdict and VulnerabilityMatcher#resolved say how. The marker is
  # the release's number, so a bookworm backport left on a trixie host (~bpo12, built from trixie's version) is matched
  # as trixie's own. Known limit (#304): trixie-backports-sloppy builds after forky's release still carry ~bpo13.
  #   ecosystem => { "marker" => what its backports' versions contain, "from" => the ecosystem they are built from }
  BACKPORTS = { "Debian:13" => { "marker" => "~bpo13+", "from" => "Debian:14" } }.freeze


  # The package manager whose version order each ecosystem's ranges use (PackageVersions).
  MANAGERS = { "Debian:13" => "dpkg", "Debian:14" => "dpkg" }.freeze

  # What the dashboard calls each ecosystem beside its OSV name (P2-D06).
  NAMES = { "Debian:13" => "Debian 13 (trixie)", "Debian:14" => "Debian 14 (forky)" }.freeze

  module_function

  def supported = TABLE.values

  # Not "name", which would hide Module#name (Rails and stub_const call it).
  def display_name(ecosystem) = NAMES[ecosystem]

  # How many active hosts (the set the Compliance page lists, owner decision on #129) report each supported
  # ecosystem's distribution, counted in the database:
  # { "Debian:13" => 4 }.
  def host_counts
    os_id = Arel.sql("lower(host_inventories.stable -> 'os' ->> 'id')")
    version = Arel.sql("host_inventories.stable -> 'os' ->> 'version_id'")
    counts = HostInventory.joins(:host).merge(Host.active).group(os_id, version).count
    supported.index_with { |ecosystem| counts.sum { |(id, version_id), count| TABLE[[ id.to_s, version_id.to_s ]] == ecosystem ? count : 0 } }
  end

  def supported?(ecosystem) = TABLE.value?(ecosystem)

  # The ecosystems the importer keeps: the fleet's, and those their backports are built from.
  def imported = (supported + BACKPORTS.values.map { |b| b["from"] }).uniq

  def imported?(ecosystem) = imported.include?(ecosystem)

  # The ecosystem a host ecosystem's backports are built from ("Debian:13" -> "Debian:14"), or nil.
  def backports_from(ecosystem) = BACKPORTS.dig(ecosystem, "from")

  # The host ecosystems whose backports are built from this one ("Debian:14" -> ["Debian:13"]).
  def backports_into(ecosystem) = BACKPORTS.select { |_, b| b["from"] == ecosystem }.keys

  # What the ecosystem's backports' versions contain ("~bpo13+"), or nil.
  def backport_marker(ecosystem) = BACKPORTS.dig(ecosystem, "marker")

  # Whether a version, on a host of the ecosystem, is one of the release's backports.
  def backport?(ecosystem, version)
    marker = backport_marker(ecosystem)
    !marker.nil? && version.to_s.include?(marker)
  end

  # A SQL LIKE pattern for the ecosystem's backports' versions, as a literal ('%~bpo13+%'), or nil. A literal, so the
  # planner can use the partial index on package_chunk_entries for backports (version LIKE '%~bpo%').
  def backport_like_sql(ecosystem)
    marker = backport_marker(ecosystem)
    marker && "version LIKE '%~bpo%' AND version LIKE #{ActiveRecord::Base.connection.quote("%#{marker}%")}"
  end

  # The ecosystem for an inventory's os hash ({"id" => "debian", "version_id" => "13"}), or nil when the
  # fleet profile has none for it.
  def for_os(os)
    return nil unless os.is_a?(Hash)

    TABLE[[ os["id"].to_s.downcase, os["version_id"].to_s ]]
  end

  def manager(ecosystem) = MANAGERS.fetch(ecosystem)
end
