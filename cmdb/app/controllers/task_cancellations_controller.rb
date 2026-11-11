# Cancelling a task or the rest of a batch from the dashboard (FR-3.2, FR-3.4, P3-S05, P3-DASH-TASKS; mockup
# cancel.html, owner decisions Q17 and Q23). Any operator may cancel any task, with a recent second factor, checked on
# the server for every POST. TaskCancellation decides what a cancel can do; the notice says what it did, in the
# mockup's words.
#
# Each cancel is a confirmation page (GET, writes nothing) that says what the cancel can and cannot do in the task's
# state now, with the code box, and a CSRF-protected POST. A refused code shows the confirmation again with why; the
# answer to a cancel goes to the task's or the batch's page.
class TaskCancellationsController < ApplicationController
  require_second_factor "cancel_task", only: %i[task batch]

  def confirm_task
    load_task
  end

  def confirm_batch
    load_batch
  end

  def task
    task = Task.includes(:host, :task_batch).find(params[:id])
    seen = params[:seen].presence_in(%w[unstarted running])
    result = TaskCancellation.cancel_task!(task, operator: current_operator, seen:)
    if result.outcome == :changed
      load_task
      flash.now[:alert] = "Nothing was done: task ##{task.id} is #{task.reload.state.humanize(capitalize: false)} now, not as this confirmation described it. Read what a cancel does now, then confirm again."
      render :confirm_task, status: :conflict
    elsif result.outcome == :finished
      redirect_to task_path(task), alert: "Not cancelled: task ##{task.id} already finished. It ended #{task.state.humanize(capitalize: false)} at #{utc(task.finished_at)}, before your request. A finished task cannot be cancelled."
    else
      redirect_to task_path(task), notice: task_notice(task, result)
    end
  end

  def batch
    batch = TaskBatch.find(params[:id])
    result = TaskCancellation.cancel_batch!(batch, operator: current_operator)
    redirect_to task_batch_path(batch), notice: batch_notice(batch, result)
  end

  private

  def load_task
    @task = Task.includes(:host, :task_batch).find(params[:id])
    @unstarted = @task.task_batch.tasks.includes(:host).where(state: TaskCancellation::UNSTARTED).where.not(id: @task.id).order(:id).to_a
  end

  def load_batch
    @batch = TaskBatch.find(params[:id])
    @tasks = @batch.tasks.includes(:host).order(:id).to_a
  end

  # A refused code: nothing was done, and the confirmation is drawn again with why (the code box says it).
  def second_factor_refused(result)
    response.headers["Cache-Control"] = "no-store"
    status = result.status == :locked ? :too_many_requests : :forbidden
    if action_name == "task"
      load_task
      render :confirm_task, status:
    else
      load_batch
      render :confirm_batch, status:
    end
  end

  def utc(time) = helpers.utc(time)

  def task_notice(task, result)
    case result.outcome
    when :cancelled
      "Task ##{task.id} cancelled. #{task.host.name} will never run it."
    when :stop_requested
      "Stop requested. Task ##{task.id} on #{task.host.name} stops when its agent next polls or reports progress, and ends as cancelled."
    when :already_requested
      "Cancel was already requested for task ##{task.id}. Nothing else was changed."
    else
      others = result.cancelled.size
      "Cancel requested. Task ##{task.id} keeps running until it finishes" +
        (others.zero? ? "." : "; #{helpers.pluralize(others, 'task')} in batch #{task.task_batch_id} that had not started #{others == 1 ? 'was' : 'were'} cancelled.")
    end
  end

  def batch_notice(batch, result)
    parts = [ "#{helpers.pluralize(result.cancelled.size, 'waiting task')} cancelled" ]
    parts << "#{helpers.pluralize(result.stopping.size, 'running task')} asked to stop" if result.stopping.any?
    parts << "#{helpers.pluralize(result.running_on.size, 'running task')} cannot be stopped safely and #{result.running_on.size == 1 ? 'runs' : 'run'} to completion" if result.running_on.any?
    "Batch #{batch.id}: #{parts.to_sentence}. #{helpers.pluralize(result.finished.size, 'finished task')} not changed. Nothing is undone."
  end
end
