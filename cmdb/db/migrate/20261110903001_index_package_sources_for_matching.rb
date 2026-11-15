# Indexes for finding the hosts an advisory import affects (P2-S11, VulnerabilityMatchJob; the upload preview's host
# count, AdvisoryUploadImportJob). Both lookups were sequential scans of their whole table, once per import.
#
# - host_packages: every query names a package's source as COALESCE(source, name) (a dpkg package with no Source
#   field is its own source), so the old index on source alone was never used and only cost writes. The expression
#   index replaces it; host_id is included so the hosts are read from the index alone.
# - vulnerability_findings: the hosts with a finding for a changed source, by ecosystem and source.
#
# Built concurrently, so package reports and matching keep writing while they build.
class IndexPackageSourcesForMatching < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    remove_index :host_packages, :source, name: "index_host_packages_on_source", algorithm: :concurrently
    add_index :host_packages, "(COALESCE(source, name)), host_id", name: "index_host_packages_on_source_package", algorithm: :concurrently
    add_index :vulnerability_findings, %i[ecosystem source host_id], name: "index_vulnerability_findings_on_ecosystem_and_source",
                                                                     algorithm: :concurrently
  end
end
