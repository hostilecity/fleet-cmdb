# Config reports (P2-CONFIG-REPORTS, P2-S02, FR-2.1, DEC-07): per host, the current facts and what the last
# report said, dated snapshots of the facts (created only when their content hash changes), and the report
# ids already processed. facts is { key => { state, value, reason } } for every manifest fact
# (AgentApi::ConfigReport), which is what the rule evaluator reads (P2-S05, P2-S06).
class CreateConfigReports < ActiveRecord::Migration[8.1]
  def change
    create_table :host_configs do |t|
      t.references :host, null: false, foreign_key: true, index: { unique: true }
      t.jsonb :facts, null: false
      t.string :content_hash, null: false, limit: 64
      t.jsonb :state_counts, null: false, default: {}
      t.integer :manifest_version, null: false # the report's, which may be older than the server's
      t.jsonb :ignored_keys, null: false, default: [] # fact keys the manifest does not have (DEC-08)
      t.uuid :report_id, null: false
      t.integer :schema_version, null: false
      t.datetime :collected_at, null: false # agent clock, display only
      t.datetime :received_at, null: false  # server clock
      t.timestamps
    end

    create_table :config_snapshots do |t|
      t.references :host, null: false, foreign_key: true, index: false
      t.jsonb :facts, null: false
      t.string :content_hash, null: false, limit: 64
      t.jsonb :state_counts, null: false, default: {}
      t.integer :manifest_version, null: false
      t.uuid :report_id, null: false
      t.datetime :collected_at, null: false
      t.datetime :received_at, null: false
    end
    add_index :config_snapshots, [ :host_id, :received_at ]
    add_index :config_snapshots, :received_at

    create_table :config_report_receipts do |t|
      t.references :host, null: false, foreign_key: true, index: false
      t.uuid :report_id, null: false
      t.datetime :received_at, null: false
    end
    add_index :config_report_receipts, [ :host_id, :report_id ], unique: true
    add_index :config_report_receipts, :received_at
  end
end
