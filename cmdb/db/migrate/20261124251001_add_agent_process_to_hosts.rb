# What the agent's heartbeats say of its process and its systemd service (#251), so a restart loop is visible: an
# agent killed at its memory limit and restarted by systemd every few minutes never reaches the start limit, and each
# new process heartbeats normally. Written by the heartbeat only when a value changes (Liveness.record_heartbeat!), so
# a steady fleet leaves the hosts row alone, as for #232's agent_recovery_coverage:
#
# - agent_process_started_at: the process's start, by the agent's clock (display; a new value is a new process);
# - agent_restarts: systemd's NRestarts for fleet-agent.service as last reported (a bigint: systemd counts to 2^32 - 1);
# - agent_last_stop_*: how the process before it stopped, as systemd told the unit's ExecStopPost=;
# - agent_recent_restarts: the server's time of each restart the heartbeats showed, newest first, at most 32
#   (Liveness::RESTART_HISTORY), from which "restarted more than N times in the last day" is counted exactly for any
#   N below 32; agent_restarted_at is its first element, the last change;
# - agent_restart_loop_at: its (limit + 1)th element (config.x.restart_loop.limit), or NULL with fewer restarts: the
#   host is in a restart loop while this is within the window, which the fleet filter's partial index reads, so the
#   filter's page reads only the hosts that loop (review of #307, S1).
#
# Nullable columns without defaults rewrite no row, and the check constraints are added NOT VALID, so nothing scans
# hosts while this transaction holds its ACCESS EXCLUSIVE lock; the next migration validates them with a lock that
# lets heartbeats keep writing (as #235 did).
class AddAgentProcessToHosts < ActiveRecord::Migration[8.1]
  def change
    change_table :hosts, bulk: true do |t|
      t.datetime :agent_process_started_at
      t.bigint :agent_restarts
      t.datetime :agent_restarted_at
      t.datetime :agent_recent_restarts, array: true
      t.datetime :agent_restart_loop_at
      t.string :agent_last_stop_result, limit: 32
      t.string :agent_last_stop_exit_code, limit: 8
      t.integer :agent_last_stop_exit_status, limit: 2
      t.datetime :agent_last_stop_at
    end
    add_check_constraint :hosts, "agent_restarts BETWEEN 0 AND 4294967295", name: "hosts_agent_restarts_valid", validate: false
    add_check_constraint :hosts, "cardinality(agent_recent_restarts) <= 32", name: "hosts_agent_recent_restarts_capped", validate: false
    add_check_constraint :hosts, "agent_last_stop_exit_code IN ('exited', 'killed', 'dumped')",
                         name: "hosts_agent_last_stop_exit_code_valid", validate: false
    add_check_constraint :hosts, "agent_last_stop_exit_status BETWEEN 0 AND 255",
                         name: "hosts_agent_last_stop_exit_status_valid", validate: false
  end
end
