# The services a host's own agent configuration allows restart_service to restart (DEC-15), as its agent reports
# them in each heartbeat (P3-A01). Bulk creation leaves out a host whose list lacks the service, so a restart is
# never sent to a VM that would refuse it (owner, P3-D01 Q7). The agent still checks its own list (AC-3.9).
class AddTaskServicesAllowedToHosts < ActiveRecord::Migration[8.1]
  def change
    add_column :hosts, :task_services_allowed, :string, array: true, null: false, default: []
  end
end
