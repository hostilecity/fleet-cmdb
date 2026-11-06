# Package reports (P2-PACKAGES, FR-2.3, DEC-07): per host, the current package set (normalised, one row per
# package, for vulnerability matching in P2-S11), what the last report said about it, dated snapshots of the
# whole set (created only when its content hash changes), and the report ids already processed.
class CreatePackages < ActiveRecord::Migration[8.1]
  def change
    # The package manager and its state as last reported, and the hash of the current set.
    create_table :host_package_sets do |t|
      t.references :host, null: false, foreign_key: true, index: { unique: true }
      t.string :manager, null: false, limit: 16
      t.string :unsupported_reason, limit: 512
      t.integer :package_count, null: false
      t.string :content_hash, null: false, limit: 64
      t.jsonb :warnings, null: false, default: []
      t.uuid :report_id, null: false
      t.integer :schema_version, null: false
      t.datetime :collected_at, null: false # agent clock, display only
      t.datetime :received_at, null: false  # server clock
      t.timestamps
      t.check_constraint "manager IN ('dpkg', 'unsupported')", name: "host_package_sets_manager_valid"
      t.check_constraint "(manager = 'unsupported') = (unsupported_reason IS NOT NULL)", name: "host_package_sets_reason_iff_unsupported"
    end

    create_table :host_packages do |t|
      t.references :host, null: false, foreign_key: true, index: false
      t.string :name, null: false, limit: 128
      t.string :architecture, null: false, limit: 32
      t.string :version, null: false, limit: 256
      t.string :source, limit: 128
    end
    add_index :host_packages, [ :host_id, :name, :architecture ], unique: true
    add_index :host_packages, :source # matching looks packages up by source package (DEC-11)

    # The whole set as it was when it changed. packages is [[name, architecture, version, source], ...] sorted
    # by name and architecture: about a third of the size of an array of objects for 3,000 packages.
    create_table :package_snapshots do |t|
      t.references :host, null: false, foreign_key: true, index: false
      t.string :manager, null: false, limit: 16
      t.string :unsupported_reason, limit: 512
      t.integer :package_count, null: false
      t.string :content_hash, null: false, limit: 64
      t.jsonb :packages, null: false
      t.jsonb :warnings, null: false, default: []
      t.uuid :report_id, null: false
      t.datetime :collected_at, null: false
      t.datetime :received_at, null: false
      t.check_constraint "manager IN ('dpkg', 'unsupported')", name: "package_snapshots_manager_valid"
    end
    add_index :package_snapshots, [ :host_id, :received_at ]
    add_index :package_snapshots, :received_at

    create_table :package_report_receipts do |t|
      t.references :host, null: false, foreign_key: true, index: false
      t.uuid :report_id, null: false
      t.datetime :received_at, null: false
    end
    add_index :package_report_receipts, [ :host_id, :report_id ], unique: true
    add_index :package_report_receipts, :received_at
  end
end
