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
  # as trixie's own.
  #
  # Sloppy backports (#304). Once forky is released, Debian starts trixie-backports-sloppy: builds of the then testing
  # release's (Debian 15's) versions for trixie. They carry the same ~bpo13+ marker (Debian's backports name a build
  # "~bpo${release}+${build}" for the release it is built for, and buster-backports-sloppy's builds from bookworm were
  # ~bpo10+1, as buster-backports' builds from bullseye), and dpkg records no suite, so a version cannot tell the two
  # apart. A backport is therefore matched against both releases, as a union, once each one's data is complete here:
  # an advisory affecting it under any of them is a verdict. OSV has Debian:15 data only once Debian 15 is testing,
  # that is after forky's release, so until then this matches as before.
  #   ecosystem => { "marker" => what its backports' versions contain, "from" => the ecosystem they are built from,
  #                  "sloppy" => the one its backports-sloppy builds are built from after "from" is released }
  BACKPORTS = { "Debian:13" => { "marker" => "~bpo13+", "from" => "Debian:14", "sloppy" => "Debian:15" } }.freeze


  # The package manager whose version order each ecosystem's ranges use (PackageVersions).
  MANAGERS = { "Debian:13" => "dpkg", "Debian:14" => "dpkg", "Debian:15" => "dpkg" }.freeze

  # What the dashboard calls each ecosystem beside its OSV name (P2-D06).
  NAMES = { "Debian:13" => "Debian 13 (trixie)", "Debian:14" => "Debian 14 (forky)", "Debian:15" => "Debian 15 (duke)" }.freeze

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
  def imported = (supported + BACKPORTS.keys.flat_map { |ecosystem| backports_releases(ecosystem) }).uniq

  def imported?(ecosystem) = imported.include?(ecosystem)

  # The ecosystem a host ecosystem's backports are built from ("Debian:13" -> "Debian:14"), or nil.
  def backports_from(ecosystem) = BACKPORTS.dig(ecosystem, "from")

  # Every ecosystem a host ecosystem's backports can be built from, that one first, then the one its backports-sloppy
  # builds are (#304): "Debian:13" -> ["Debian:14", "Debian:15"]; [] for none.
  def backports_releases(ecosystem) = BACKPORTS.fetch(ecosystem, {}).values_at("from", "sloppy").compact

  # The host ecosystems whose backports can be built from this one ("Debian:14" or "Debian:15" -> ["Debian:13"]).
  def backports_into(ecosystem) = BACKPORTS.keys.select { |into| backports_releases(into).include?(ecosystem) }

  # Whether the ecosystem is the one a host ecosystem's backports-sloppy builds are built from (#304).
  def sloppy?(ecosystem) = BACKPORTS.values.any? { |b| b["sloppy"] == ecosystem }

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
