# Whether recovery mode is set up on the host (#232, ADR 0030), from the `units.recovery` of its last heartbeat:
# set_up (true), not_set_up (false), or unchecked (null: the agent could not check, re-review of #235). NULL when the
# agent does not report it (an older agent), or no heartbeat has come. The heartbeat writes the hosts row only when the
# value changes (Liveness.record_heartbeat!), so a steady fleet leaves it alone. Adding a nullable column without a
# default changes no row, so it is instant; its index is built concurrently in the next migration.
class AddAgentRecoveryCoverageToHosts < ActiveRecord::Migration[8.1]
  def change
    add_column :hosts, :agent_recovery_coverage, :string, limit: 16
    add_check_constraint :hosts, "agent_recovery_coverage IN ('set_up', 'not_set_up', 'unchecked')",
                         name: "hosts_agent_recovery_coverage_valid", validate: true
  end
end
