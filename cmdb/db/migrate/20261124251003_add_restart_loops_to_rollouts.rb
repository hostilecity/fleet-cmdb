# Restart loops in rollouts (#251, ADR 0018):
#
# - rollout_hosts.state gains restart_loop: a host whose agent restarted more than the restart-loop limit within its
#   window after the update counts as failed for its stage. The check is replaced NOT VALID: every heartbeat reads
#   rollout_hosts (the offer lookup), and the table holds one row per host per rollout, so a validating check would scan
#   it under ACCESS EXCLUSIVE while heartbeats queue (review of #307, S5). The next migration validates it outside a
#   transaction. Existing rows already satisfy it: it only allows one more state.
# - rollout_hosts.restarts_before_offer: the host's restarts within the window before its first offer, set by that
#   offer (owner decision 2026-11-23, S6): a host already looping before the update does not count towards the halt.
#   NULL for a host not offered yet.
# - rollouts.stage_confirmed_at: when every host of the current stage had confirmed. The next stage opens, or the last
#   completes the rollout, only FLEET_ROLLOUT_STAGE_OBSERVE_MINUTES later (owner decision 2026-11-23, S4).
#
# Nullable columns without defaults rewrite no row.
class AddRestartLoopsToRollouts < ActiveRecord::Migration[8.1]
  BEFORE = %w[pending updating confirmed failed rolled_back unconfirmed].freeze
  AFTER = [ *BEFORE, "restart_loop" ].freeze

  def up
    add_column :rollout_hosts, :restarts_before_offer, :integer, limit: 2
    add_column :rollouts, :stage_confirmed_at, :datetime
    replace_check(AFTER, validate: false)
  end

  def down
    replace_check(BEFORE, validate: true)
    remove_column :rollouts, :stage_confirmed_at
    remove_column :rollout_hosts, :restarts_before_offer
  end

  private

  def replace_check(states, validate:)
    remove_check_constraint :rollout_hosts, name: "rollout_hosts_state_valid"
    add_check_constraint :rollout_hosts, "state IN (#{states.map { |s| connection.quote(s) }.join(', ')})",
                         name: "rollout_hosts_state_valid", validate:
  end
end
