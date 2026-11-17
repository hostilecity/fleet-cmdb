# Drops the per-host package storage once every list is in a set (#196, ADR 0028, the clean-up): host_packages, the
# snapshots' JSON lists, and the finding columns that are now chunk verdicts (source, ecosystem, installed_version,
# fixed_version) with their indexes. Refuses while any dpkg snapshot or host has no set, which would lose its list.
#
# Each drop is catalog-only. The space of the dropped finding columns returns as rows are rewritten; a large fleet that
# wants it at once rebuilds the table (ADR 0028). Not reversible: no backward compatibility is needed (NFR-5), and the
# lists would have to be rebuilt from the sets.
class DropHostPackages < ActiveRecord::Migration[8.1]
  def up
    unset = select_value("SELECT count(*) FROM package_snapshots WHERE manager = 'dpkg' AND package_set_id IS NULL").to_i +
            select_value("SELECT count(*) FROM host_package_sets WHERE manager = 'dpkg' AND package_set_id IS NULL").to_i
    raise "#{unset} dpkg package snapshots and hosts have no package set; run BackfillPackageSets again (bin/rails db:migrate:redo VERSION=20261116196003)" if unset.positive?

    drop_table :host_packages
    remove_column :package_snapshots, :packages
    remove_index :vulnerability_findings, name: "index_vulnerability_findings_on_host_id_and_source"
    remove_index :vulnerability_findings, name: "index_vulnerability_findings_on_ecosystem_and_source"
    remove_column :vulnerability_findings, :source
    remove_column :vulnerability_findings, :ecosystem
    remove_column :vulnerability_findings, :installed_version
    remove_column :vulnerability_findings, :fixed_version
  end

  def down = raise(ActiveRecord::IrreversibleMigration, "the package lists are in package sets now; rebuild the database instead (NFR-5)")
end
