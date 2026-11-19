# Drops the per-host package storage once every list is in a set (#196, ADR 0028, the clean-up): host_packages, the
# snapshots' JSON lists, and the finding columns that are now chunk verdicts (source, ecosystem, installed_version,
# fixed_version) with their indexes. Refuses while any dpkg snapshot or host has no set, which would lose its list, or
# any finding's details are not copied yet.
#
# Each drop is catalog-only, under ACCESS EXCLUSIVE locks on three tables, so it waits at most LOCK_TIMEOUT for them
# (the deploy has stopped the server; a straggler is the backup or a console). The space of the dropped finding columns
# returns only as rows are rewritten: an upgraded database keeps its larger rows until the table is rebuilt (ADR 0028).
# Not reversible: no backward compatibility is needed (NFR-5).
class DropHostPackages < ActiveRecord::Migration[8.1]
  LOCK_TIMEOUT = "10s".freeze

  def up
    execute "SET LOCAL lock_timeout = '#{LOCK_TIMEOUT}'"
    findings = select_value("SELECT count(*) FROM vulnerability_findings WHERE last_ecosystem IS NULL").to_i
    unset = select_value("SELECT count(*) FROM package_snapshots WHERE manager = 'dpkg' AND package_set_id IS NULL").to_i +
            select_value("SELECT count(*) FROM host_package_sets WHERE manager = 'dpkg' AND package_set_id IS NULL").to_i
    if unset.positive? || findings.positive?
      raise "#{BackfillPackageSets::UPGRADE_STEP}: #{unset} dpkg package snapshots and hosts have no package set and #{findings} findings " \
            "have no copied details, so the old storage is kept. #{BackfillPackageSets::RUNBOOK}"
    end

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
