# The total time a rollout has been halted, so a resume does not make every offer of its open stage due at once
# (#199): an offer is due at rollout_hosts.offer_at plus this many seconds (Rollouts.offer_scope).
class AddHaltedSecondsToRollouts < ActiveRecord::Migration[8.1]
  def change
    add_column :rollouts, :halted_seconds, :integer, default: 0, null: false
  end
end
