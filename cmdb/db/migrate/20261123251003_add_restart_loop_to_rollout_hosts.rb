# A rollout host whose agent restarted more than the restart-loop limit within its window after it was sent the update
# (#251, ADR 0018) is marked restart_loop: it counts as failed for the stage, so the rollout halts. rollout_hosts holds
# one row per host per rollout and is not on the heartbeat's write path, so the check is replaced in place.
class AddRestartLoopToRolloutHosts < ActiveRecord::Migration[8.1]
  BEFORE = %w[pending updating confirmed failed rolled_back unconfirmed].freeze
  AFTER = [ *BEFORE, "restart_loop" ].freeze

  def up = replace_check(AFTER)

  def down = replace_check(BEFORE)

  private

  def replace_check(states)
    remove_check_constraint :rollout_hosts, name: "rollout_hosts_state_valid"
    add_check_constraint :rollout_hosts, "state IN (#{states.map { |s| connection.quote(s) }.join(', ')})", name: "rollout_hosts_state_valid"
  end
end
