# Restart loops in rollouts (#251, ADR 0018):
#
# - rollout_hosts.state gains restart_loop: a host whose agent restarted more than the restart-loop limit within its
#   window after the update counts as failed for its stage. The check is replaced NOT VALID: every heartbeat reads
#   rollout_hosts (the offer lookup), and the table holds one row per host per rollout, so a validating check would scan
#   it under ACCESS EXCLUSIVE while heartbeats queue (review of #307, S5). The next migration validates it outside a
#   transaction. Existing rows already satisfy it: it only allows one more state.
# - rollout_hosts.restarts_before_offer: the host's restarts within the window before its first offer, set by that
#   offer (owner decision 2026-11-23, S6): a host already looping before the update does not count towards the halt.
#   With it, the restart-loop limit and window in force at that offer (restart_limit, restart_window_hours; re-check
#   of #307, N2), and whether an earlier rollout marked the host restart_loop within that window
#   (restart_loop_before), which ends the exemption (owner decision 2026-11-24). NULL for a host not offered yet.
# - rollouts.stage_confirmed_at: when every host of the current stage had confirmed, and last_confirmed_at: when any
#   host of the rollout last confirmed. The next stage opens, or the last completes the rollout, only
#   FLEET_ROLLOUT_STAGE_OBSERVE_MINUTES after the later of the two (owner decision 2026-11-23; a host of an earlier stage
#   that confirms after an early Advance is observed too, re-check of #307, S4).
#
# Nullable columns without defaults rewrite no row. ACCESS EXCLUSIVE on rollout_hosts and rollouts is held for that
# short time only, and given up if not granted within 3 s: while it waits, every heartbeat's offer read queues behind
# it (re-check of #307, N4).
class AddRestartLoopsToRollouts < ActiveRecord::Migration[8.1]
  BEFORE = %w[pending updating confirmed failed rolled_back unconfirmed].freeze
  AFTER = [ *BEFORE, "restart_loop" ].freeze

  def up
    execute "SET LOCAL lock_timeout = '3s'"
    change_table :rollout_hosts, bulk: true do |t|
      t.integer :restarts_before_offer, limit: 2
      t.integer :restart_limit, limit: 2
      t.integer :restart_window_hours, limit: 2
      t.boolean :restart_loop_before
    end
    change_table :rollouts, bulk: true do |t|
      t.datetime :stage_confirmed_at
      t.datetime :last_confirmed_at
    end
    replace_check(AFTER, validate: false)
  end

  def down
    execute "SET LOCAL lock_timeout = '3s'"
    replace_check(BEFORE, validate: true)
    remove_columns :rollouts, :stage_confirmed_at, :last_confirmed_at
    remove_columns :rollout_hosts, :restarts_before_offer, :restart_limit, :restart_window_hours, :restart_loop_before
  end

  private

  def replace_check(states, validate:)
    remove_check_constraint :rollout_hosts, name: "rollout_hosts_state_valid"
    add_check_constraint :rollout_hosts, "state IN (#{states.map { |s| connection.quote(s) }.join(', ')})",
                         name: "rollout_hosts_state_valid", validate:
  end
end
