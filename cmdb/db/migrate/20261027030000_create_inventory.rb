# Inventory reports (P1-INVENTORY, FR-1.3, DEC-07, FR-S.1): the host's current inventory, dated snapshots
# of the stable fields (only when they change), the report ids already processed per host, and the
# clone-detection warning.
class CreateInventory < ActiveRecord::Migration[8.1]
  def change
    create_table :host_inventories do |t|
      t.references :host, null: false, foreign_key: true, index: { unique: true }
      t.jsonb :stable, null: false
      t.jsonb :volatile, null: false
      t.jsonb :warnings, null: false, default: []
      t.string :stable_hash, null: false, limit: 64
      t.uuid :report_id, null: false
      t.integer :schema_version, null: false
      t.datetime :collected_at, null: false # agent clock, display only
      t.datetime :received_at, null: false  # server clock
      t.timestamps
    end

    create_table :inventory_snapshots do |t|
      t.references :host, null: false, foreign_key: true, index: false
      t.jsonb :stable, null: false
      t.jsonb :warnings, null: false, default: []
      t.string :stable_hash, null: false, limit: 64
      t.uuid :report_id, null: false
      t.datetime :collected_at, null: false
      t.datetime :received_at, null: false
    end
    add_index :inventory_snapshots, [ :host_id, :received_at ]
    add_index :inventory_snapshots, :received_at

    # Report ids already processed, so a retried report is answered as a duplicate (DEC-07).
    create_table :inventory_report_receipts do |t|
      t.references :host, null: false, foreign_key: true, index: false
      t.uuid :report_id, null: false
      t.datetime :received_at, null: false
    end
    add_index :inventory_report_receipts, [ :host_id, :report_id ], unique: true
    add_index :inventory_report_receipts, :received_at

    # FR-S.1: a credential used from a machine other than the one it was enrolled on. Cleared by re-enrollment.
    add_column :hosts, :machine_id_mismatch_at, :datetime
    add_column :hosts, :reported_machine_id, :string, limit: 32
  end
end
