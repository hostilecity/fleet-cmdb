module DebianTriage
  # The tracker's release for a host's distribution (P2-S16, ADR 0022, item 4), from the table in
  # config/triage_releases.yml (DebianTriage.config.releases), so adding a release is a data change. Nothing
  # here assumes one release: a host whose os-release has no VERSION_ID maps through a null version_id (sid).
  module Releases
    # The ids the advisories can join on; the tracker's other ids ("TEMP-0000000-ABCDEF") are counted, not stored.
    CVE = /\ACVE-\d{4}-\d{4,19}\z/

    module_function

    def table = DebianTriage.config.releases

    # Every release in the table, sorted.
    def names = table.values.uniq.sort

    # The releases the import keeps (owner decision on #135): those an active host's inventory maps to, sorted. A
    # release no active host reports is not imported, and its stored data is dropped.
    def in_use
      os_id = Arel.sql("lower(host_inventories.stable -> 'os' ->> 'id')")
      version = Arel.sql("host_inventories.stable -> 'os' ->> 'version_id'")
      HostInventory.joins(:host).merge(Host.active).distinct.pluck(os_id, version)
                   .filter_map { |id, version_id| for_os("id" => id, "version_id" => version_id) }.uniq.sort
    end

    # The release for an inventory's os hash ({"id" => "debian", "version_id" => "13"}), or nil.
    def for_os(os)
      return nil unless os.is_a?(Hash)

      table[[ os["id"].to_s.downcase, os["version_id"].presence&.to_s ]]
    end
  end
end
