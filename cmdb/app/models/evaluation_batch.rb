# One batch of an EvaluationRun (#197): a keyset range of host ids, first_host_id to last_host_id inclusive, holding
# host_count hosts when the run was split. Deleted when its batch is counted (EvaluationRun.batch_done!).
class EvaluationBatch < ApplicationRecord
  belongs_to :evaluation_run, inverse_of: :batches

  def host_range = first_host_id..last_host_id
end
