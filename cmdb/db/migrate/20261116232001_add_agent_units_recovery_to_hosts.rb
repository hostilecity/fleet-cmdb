# Whether recovery mode is set up on the host (#232, ADR 0030): the `units.recovery` of its last heartbeat. NULL when
# the agent does not report it (an older agent), or no heartbeat has come. The heartbeat writes the hosts row only when
# the value changes (Liveness.record_heartbeat!), so a steady fleet leaves it alone. Adding a nullable column without a
# default changes no row, so it is instant; its index is built concurrently in the next migration.
class AddAgentUnitsRecoveryToHosts < ActiveRecord::Migration[8.1]
  def change
    add_column :hosts, :agent_units_recovery, :boolean
  end
end
