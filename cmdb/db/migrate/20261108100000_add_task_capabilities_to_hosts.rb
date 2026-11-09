# What a host's agent says about tasks (FR-3.1, P3-A01): the catalog version compiled into it, the task types it
# implements, and the types its local configuration enables. Bulk creation (P3-S02) targets only hosts that support
# and enable a type, so until an agent reports these, no task is created for its host. Reported by the agent;
# the API that records them comes with the agent's capability report (P3-A01).
class AddTaskCapabilitiesToHosts < ActiveRecord::Migration[8.1]
  def change
    change_table :hosts, bulk: true do |t|
      t.integer :task_catalog_version
      t.string :task_types_supported, array: true, null: false, default: []
      t.string :task_types_enabled, array: true, null: false, default: []
      t.datetime :task_capabilities_reported_at
    end
  end
end
