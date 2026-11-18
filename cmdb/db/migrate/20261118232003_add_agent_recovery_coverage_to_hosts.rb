# Whether recovery mode is set up on the host (#232, ADR 0030), from the `units.recovery` of its last heartbeat:
# set_up (true), not_set_up (false), or unchecked (null: the agent could not check, re-review of #235). NULL when the
# agent does not report it (an older agent), or no heartbeat has come. The heartbeat writes the hosts row only when the
# value changes (Liveness.record_heartbeat!), so a steady fleet leaves it alone.
#
# Adding a nullable column without a default rewrites no row, and the check constraint is added NOT VALID, so neither
# scans hosts while this transaction holds its ACCESS EXCLUSIVE lock (a validating ADD CONSTRAINT took 0.35 to 0.6 s on
# 1M hosts; final check of #235). The next migration validates it outside a transaction, with a lock that lets
# heartbeats keep writing. New rows are checked from now on either way.
#
# Versions 20261118232003 and 232004 replace 20261116232001 and 232002 of earlier revisions of this branch (a boolean
# agent_units_recovery): a database that ran those must be rebuilt (NFR-5); this one then fails on the index name
# rather than silently keeping the old column.
class AddAgentRecoveryCoverageToHosts < ActiveRecord::Migration[8.1]
  def change
    add_column :hosts, :agent_recovery_coverage, :string, limit: 16
    add_check_constraint :hosts, "agent_recovery_coverage IN ('set_up', 'not_set_up', 'unchecked')",
                         name: "hosts_agent_recovery_coverage_valid", validate: false
  end
end
