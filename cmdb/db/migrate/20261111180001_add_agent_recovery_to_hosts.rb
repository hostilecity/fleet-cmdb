# Agent recovery mode (#180, ADR 0030): what the last heartbeat said about it, stored by the heartbeat's own UPDATE.
#
# agent_recovery_since is the server's clock at the first heartbeat of the episode that carried `recovery`, and is
# what "recovering" means on the dashboard; NULL in normal mode. The agent's own times (when the episode began, when it
# will next try normal mode) are kept for display only, like agent_reported_at. The reason is the agent's text, at
# most 256 characters (heartbeat.request).
class AddAgentRecoveryToHosts < ActiveRecord::Migration[8.1]
  def change
    change_table :hosts, bulk: true do |t|
      t.datetime :agent_recovery_since
      t.datetime :agent_recovery_entered_at
      t.datetime :agent_recovery_retry_at
      t.string :agent_recovery_reason, limit: 256
    end
  end
end
