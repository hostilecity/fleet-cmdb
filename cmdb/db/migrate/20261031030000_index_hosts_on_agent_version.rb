# Hosts are looked up by the agent version they run: the release delete guard (agent_releases_guard),
# AgentRelease#in_use?, the Agents page's per-release host count, and, with P1-UPDATES, rollouts. Without an
# index each is a sequential scan of hosts, seconds at a million hosts. Partial on the fleet (Host.in_fleet),
# as every one of those queries is. Built concurrently, so hosts keep reporting while it builds (review of #74).
class IndexHostsOnAgentVersion < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    add_index :hosts, :agent_version, where: "enrollment_state <> 'retired'", name: "index_hosts_in_fleet_on_agent_version",
                                      algorithm: :concurrently
  end
end
