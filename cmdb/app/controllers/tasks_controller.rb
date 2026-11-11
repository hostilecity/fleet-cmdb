# Tasks (FR-3.4, P3-DASH-TASKS; mockups tasks.html, task.html, task-states.html, owner decisions Q2, Q18, Q19, Q22).
# Read-only, behind sign-in like every dashboard page.
#
# - index: every task, newest first, filterable by host, type, state, and batch (TaskList). Filters and the page
#   position are query parameters, so a filtered view can be bookmarked.
# - show: one task: its state and reason in words, the task facts and parameters, what it reported, the timeline of
#   state changes with the server's and the agent's times, the output as escaped text, and its audit entries.
# - output: the stored output as a plain-text download, never as a page.
#
# Task output is untrusted text from a VM (FR-3.3): it was sanitised when it was stored (TaskOutput), and every view
# renders it escaped. Without a second factor an operator still reads every task page (Q12).
class TasksController < ApplicationController
  def index
    query = request.query_parameters.slice(*TaskList::PARAMS.map(&:to_s)).select { |_, value| value.is_a?(String) }
    # The filter form sends every field; the address keeps only the ones in use.
    return redirect_to(helpers.task_list_path(query.reject { |_, value| value.blank? })) if query.any? { |_, value| value.blank? }

    @list = TaskList.new(query.with_indifferent_access)
  end

  def show
    @task = Task.includes(:host, :late_result, :cancel_requested_by, task_batch: :operator).find(params[:id])
    @batch = @task.task_batch
    @batch_size = @batch.tasks.count
    @unstarted_others = @batch.tasks.where(state: TaskCancellation::UNSTARTED).where.not(id: @task.id).count
    @entries = AuditEntry.where(target_type: "Task", target_id: @task.id).order(:occurred_at, :id).to_a
    @records = AuditLog::Records.for(@entries)
  end

  def output
    task = Task.find(params[:id])
    return head(:not_found) if task.output.nil?

    send_data task.output, type: "text/plain; charset=utf-8", disposition: "attachment", filename: "task-#{task.id}-output.txt"
  end
end
