# A package set holding a chunk a triage run changed (VT-BUCKETS #259, EvaluationRun::Triage), found once as the run
# is prepared: the run's batches find their hosts by probing these rows. Deleted with its run.
class TriageRunSet < ApplicationRecord
  self.primary_key = %i[evaluation_run_id package_set_id]
end
