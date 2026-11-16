# The compliance summaries' trigger function plans its transition-table queries for each statement (#224): version 2
# of host_compliance_summaries_changed runs them through EXECUTE. Statically, PL/pgSQL kept the plan it made first in a
# session, for however many rows that statement changed, so after a one-row update a bulk UPDATE of hosts ran a nested
# loop over its transition tables: 29 to 40 s for 20,000 rows instead of about 0.1 s.
#
# CREATE OR REPLACE in place: the triggers that call it stay as they are.
class PlanSummaryTriggerQueriesPerStatement < ActiveRecord::Migration[8.1]
  def up
    execute Rails.root.join("db/functions/host_compliance_summaries_changed_v02.sql").read
  end

  def down
    execute Rails.root.join("db/functions/host_compliance_summaries_changed_v01.sql").read
  end
end
