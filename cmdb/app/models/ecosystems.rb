# Which advisory ecosystem a host's distribution belongs to (DEC-01, DEC-11, P2-S11). Advisories are scoped to
# a distribution release ("Debian:13" in OSV), and a host is matched only against its own release's data, from
# the os id and version_id its inventory reports. The table is the fleet profile: adding a distribution or
# release here needs a new decision (DEC-01). The importer keeps only the ecosystems listed here.
module Ecosystems
  # [os id, version_id] => OSV ecosystem
  TABLE = { [ "debian", "13" ] => "Debian:13" }.freeze

  # The package manager whose version order each ecosystem's ranges use (PackageVersions).
  MANAGERS = { "Debian:13" => "dpkg" }.freeze

  # What the dashboard calls each ecosystem beside its OSV name (P2-D06).
  NAMES = { "Debian:13" => "Debian 13 (trixie)" }.freeze

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

  # The ecosystem for an inventory's os hash ({"id" => "debian", "version_id" => "13"}), or nil when the
  # fleet profile has none for it.
  def for_os(os)
    return nil unless os.is_a?(Hash)

    TABLE[[ os["id"].to_s.downcase, os["version_id"].to_s ]]
  end

  def manager(ecosystem) = MANAGERS.fetch(ecosystem)
end
