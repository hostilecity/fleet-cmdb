# Skipped packages and an unreadable package database (P2-S08, FR-2.3). A report may name packages the agent
# saw but did not list as installed (an interrupted installation): they are stored with the set and with its
# snapshot, so a diff can show them as skipped, not removed. A host whose dpkg database could not be listed
# reports `unreadable` with a reason, like `unsupported`: the reason column keeps its name. Rolling back refuses
# while unreadable rows exist (review of #121).
class AddSkippedAndUnreadableToPackages < ActiveRecord::Migration[8.1]
  def change
    add_column :host_package_sets, :skipped, :jsonb, null: false, default: []
    add_column :package_snapshots, :skipped, :jsonb, null: false, default: []

    reversible do |direction|
      direction.up do
        remove_check_constraint :host_package_sets, name: "host_package_sets_manager_valid"
        remove_check_constraint :host_package_sets, name: "host_package_sets_reason_iff_unsupported"
        remove_check_constraint :package_snapshots, name: "package_snapshots_manager_valid"
        add_check_constraint :host_package_sets, "manager IN ('dpkg', 'unsupported', 'unreadable')", name: "host_package_sets_manager_valid"
        add_check_constraint :host_package_sets, "(manager = 'dpkg') = (unsupported_reason IS NULL)", name: "host_package_sets_reason_iff_not_dpkg"
        add_check_constraint :package_snapshots, "manager IN ('dpkg', 'unsupported', 'unreadable')", name: "package_snapshots_manager_valid"
      end
      direction.down do
        # The old constraints cannot hold an unreadable set or snapshot. Turning one into `unsupported` would
        # claim the host has no dpkg and drop the last known packages from the history, so the rollback refuses
        # instead and says which rows are in the way (review of #121).
        unreadable = %w[host_package_sets package_snapshots].to_h { |table| [ table, select_value("SELECT count(*) FROM #{table} WHERE manager = 'unreadable'").to_i ] }
        if unreadable.values.any?(&:positive?)
          raise ActiveRecord::IrreversibleMigration,
                "cannot roll back: #{unreadable.map { |table, n| "#{n} #{table} rows" }.join(' and ')} have manager 'unreadable', which the " \
                "previous constraints do not allow; delete or correct them first (for example by sending a readable package report)"
        end
        remove_check_constraint :host_package_sets, name: "host_package_sets_manager_valid"
        remove_check_constraint :host_package_sets, name: "host_package_sets_reason_iff_not_dpkg"
        remove_check_constraint :package_snapshots, name: "package_snapshots_manager_valid"
        add_check_constraint :host_package_sets, "manager IN ('dpkg', 'unsupported')", name: "host_package_sets_manager_valid"
        add_check_constraint :host_package_sets, "(manager = 'unsupported') = (unsupported_reason IS NOT NULL)", name: "host_package_sets_reason_iff_unsupported"
        add_check_constraint :package_snapshots, "manager IN ('dpkg', 'unsupported')", name: "package_snapshots_manager_valid"
      end
    end
  end
end
