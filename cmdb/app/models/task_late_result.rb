# A task result that arrived after the server had already ended the task itself: timed out, expired, failed with
# lease_expired, cancelled, or refused at claim (P3-S04, threat model L4). The task's state never changes once it
# is terminal, so the agent's account is kept here, beside it, as an annotation: at most one per task, never
# changed or deleted (task_late_results_guard). Created only by AgentTasks.record_result!. Output is sanitised
# and limited as for an applied result (TaskOutput).
class TaskLateResult < ApplicationRecord
  belongs_to :task

  validates :outcome, inclusion: { in: AgentTasks::OUTCOMES }
  validates :report_id, :digest, :agent_finished_at, :received_at, presence: true

  before_destroy { raise ActiveRecord::ReadOnlyRecord, "late task results are never deleted" }

  def readonly? = super || persisted?
end
