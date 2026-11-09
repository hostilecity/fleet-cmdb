# One operator request to run a task type on one or more hosts (FR-3.2, P3-S02): the type, the validated
# parameters, how the hosts were selected (explicit ids or a tag), the hosts the selection resolved to when it was
# made, the hosts excluded and why, and the catalog it was checked against. It has one independent Task per
# targeted host. Created only by TaskBatches.create!; never changed or deleted (task_batches_guard).
class TaskBatch < ApplicationRecord
  SELECTION_METHODS = %w[explicit tag].freeze

  belongs_to :operator
  has_many :tasks, dependent: :restrict_with_exception

  validates :selection_method, inclusion: { in: SELECTION_METHODS }

  def readonly? = super || persisted?

  # Tasks per state, for batch progress (FR-3.4): { "succeeded" => 6, "running" => 1, ... }, every state listed.
  def state_counts = Task::STATES.index_with(0).merge(tasks.group(:state).count)
end
