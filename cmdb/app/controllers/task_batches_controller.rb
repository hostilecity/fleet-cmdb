# Batch progress (FR-3.4, P3-DASH-TASKS; mockups batch.html and batch-partial.html, owner decisions Q14 to Q17):
# what was asked for, a count for every state worked out from the task rows on every render (never kept as a separate
# number), per-host rows with problems first, the hosts left out with the reason recorded when the batch was created,
# and the way to cancel the rest. The page refreshes itself when a task changes (TaskBroadcast). Read-only.
class TaskBatchesController < ApplicationController
  def show
    @batch = TaskBatch.includes(:operator).find(params[:id])
    @tasks = @batch.tasks.includes(:host, :cancel_requested_by).order(:id).to_a
    @counts = Task::STATES.index_with(0).merge(@tasks.map(&:state).tally)
    @excluded_hosts = Host.where(id: @batch.excluded_hosts.pluck("host_id")).index_by(&:id)
  end
end
