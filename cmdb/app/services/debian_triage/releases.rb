module DebianTriage
  # The tracker's release for a host's distribution (P2-S16, ADR 0022, item 4), from the table in
  # config/triage_releases.yml (DebianTriage.config.releases), so adding a release is a data change. Nothing
  # here assumes one release: a host whose os-release has no VERSION_ID maps through a null version_id (sid).
  module Releases
    # The ids the advisories can join on; the tracker's other ids ("TEMP-0000000-ABCDEF") are counted, not stored.
    CVE = /\ACVE-\d{4}-\d{4,19}\z/

    module_function

    def table = DebianTriage.config.releases

    # Every release the import keeps, sorted.
    def names = table.values.uniq.sort

    # The release for an inventory's os hash ({"id" => "debian", "version_id" => "13"}), or nil.
    def for_os(os)
      return nil unless os.is_a?(Hash)

      table[[ os["id"].to_s.downcase, os["version_id"].presence&.to_s ]]
    end
  end
end
