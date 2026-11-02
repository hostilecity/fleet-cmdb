# Staged agent rollouts and the update history (P1-UPDATES, ADR 0018).
#
# - rollouts: one release going out in stages. At most one is open (running or halted) at a time. The target
#   release is a restricting foreign key, so a release a rollout targets can never be deleted.
# - rollout_hosts: the hosts a rollout has reached so far and how each is doing. A stage's hosts are chosen
#   when it opens.
# - agent_updates: the history of outcomes agents reported, one row per accepted result.
class CreateRollouts < ActiveRecord::Migration[8.1]
  def change
    create_table :rollouts do |t|
      t.references :agent_release, null: false, foreign_key: { on_delete: :restrict }, index: true
      t.string :state, null: false, default: "running", limit: 16
      # Set while the rollout is open (running or halted), so a unique index allows only one at a time.
      t.integer :open_slot, default: 1
      t.bigint :canary_host_ids, array: true, null: false, default: []
      t.string :canary_tag, limit: 32
      # Stage 0 is the canaries; stage n (1-based) brings the rollout to stage_percents[n - 1] percent.
      t.integer :stage_percents, array: true, null: false, default: [ 25, 100 ]
      t.integer :current_stage, null: false, default: 0
      t.datetime :stage_opened_at, null: false
      t.text :halt_reason
      t.references :started_by, null: false, foreign_key: { to_table: :operators }, index: false
      t.references :halted_by, foreign_key: { to_table: :operators }, index: false
      t.references :resumed_by, foreign_key: { to_table: :operators }, index: false
      t.datetime :started_at, null: false
      t.datetime :halted_at
      t.datetime :resumed_at
      t.datetime :finished_at
      t.timestamps
    end
    add_index :rollouts, :open_slot, unique: true, name: "index_rollouts_one_open"
    add_check_constraint :rollouts, "state IN ('running', 'halted', 'completed', 'cancelled')", name: "rollouts_state_valid"
    add_check_constraint :rollouts, "(open_slot IS NOT NULL) = (state IN ('running', 'halted'))", name: "rollouts_open_slot_matches_state"
    add_check_constraint :rollouts, "cardinality(canary_host_ids) > 0 OR canary_tag IS NOT NULL", name: "rollouts_have_canaries"
    add_check_constraint :rollouts, "current_stage >= 0 AND current_stage <= cardinality(stage_percents)", name: "rollouts_stage_in_range"

    create_table :rollout_hosts do |t|
      t.references :rollout, null: false, foreign_key: true, index: false
      t.references :host, null: false, foreign_key: true, index: true
      t.integer :stage, null: false
      t.string :state, null: false, default: "pending", limit: 16
      # The directive is not sent before this time: opening a stage spreads its hosts over a window, so many
      # VMs behind one address do not hit the release download limit together (P1-UPDATES).
      t.datetime :offer_at, null: false
      t.datetime :offered_at
      t.datetime :resolved_at
      t.timestamps
    end
    add_index :rollout_hosts, %i[rollout_id host_id], unique: true
    add_index :rollout_hosts, %i[rollout_id stage state]
    add_index :rollout_hosts, :offered_at, where: "state = 'updating'", name: "index_rollout_hosts_updating"
    add_check_constraint :rollout_hosts, "state IN ('pending', 'updating', 'confirmed', 'failed', 'rolled_back', 'unconfirmed')",
                         name: "rollout_hosts_state_valid"

    create_table :agent_updates do |t|
      t.references :host, null: false, foreign_key: true, index: false
      t.references :rollout, null: false, foreign_key: true, index: true
      t.uuid :report_id, null: false
      t.string :version, null: false, limit: 64
      t.string :outcome, null: false, limit: 16
      t.text :reason
      t.string :reported_agent_version, null: false, limit: 64
      t.datetime :occurred_at, null: false
      t.datetime :received_at, null: false
    end
    add_index :agent_updates, %i[host_id report_id], unique: true
    add_index :agent_updates, %i[host_id received_at]
    add_check_constraint :agent_updates, "outcome IN ('succeeded', 'failed', 'rolled_back')", name: "agent_updates_outcome_valid"
  end
end
