# Tasks (FR-3.4). For now only the way into the create flow and the most recent batches; the task list with its
# filters, the task pages, and batch progress are P3-DASH-TASKS (#33), which replaces this page.
class TasksController < ApplicationController
  RECENT_BATCHES = 20

  def index
    @batches = TaskBatch.includes(:operator).order(created_at: :desc, id: :desc).limit(RECENT_BATCHES)
    @counts = Task.where(task_batch_id: @batches.map(&:id)).group(:task_batch_id).count
  end
end
