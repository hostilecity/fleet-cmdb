# A chunk whose base bucket or KEV flag a triage run changed (VT-BUCKETS #259, EvaluationRun::Triage): the run's hosts
# are those on sets holding one. Deleted with its run.
class TriageRunChunk < ApplicationRecord
  self.primary_key = %i[evaluation_run_id package_chunk_id]

  belongs_to :evaluation_run, inverse_of: :triage_chunks
end
