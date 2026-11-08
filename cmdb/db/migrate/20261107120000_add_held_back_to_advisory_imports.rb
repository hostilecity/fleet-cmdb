# A full import the withdrawal guard refused is held back, not failed (review of #131): nothing was stored, as for
# a failure, but it is not retried, counted as a failed refresh, or shown as a failed job, and it is audited as
# advisory.import_held_back. Rows recorded as failed with the counts are moved to the new state.
class AddHeldBackToAdvisoryImports < ActiveRecord::Migration[8.1]
  def up
    remove_check_constraint :advisory_imports, name: "advisory_imports_state_valid"
    add_check_constraint :advisory_imports, "state IN ('queued', 'importing', 'succeeded', 'failed', 'held_back')", name: "advisory_imports_state_valid"
    execute "UPDATE advisory_imports SET state = 'held_back' WHERE state = 'failed' AND counts ? 'would_withdraw'"
  end

  def down
    execute "UPDATE advisory_imports SET state = 'failed' WHERE state = 'held_back'"
    remove_check_constraint :advisory_imports, name: "advisory_imports_state_valid"
    add_check_constraint :advisory_imports, "state IN ('queued', 'importing', 'succeeded', 'failed')", name: "advisory_imports_state_valid"
  end
end
