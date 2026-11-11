# Cancelling a task or the rest of a batch from the dashboard (FR-3.2, FR-3.4, P3-S05; mockup cancel.html). Any
# operator may cancel any task, with a recent second factor (owner decision Q23), checked on the server for every
# request. TaskCancellation decides what a cancel can do; the notice says what it did, in the mockup's words.
#
# The confirmation dialogs and the task and batch pages are P3-DASH-TASKS (#33): until then a cancel is a POST from
# wherever it was made, and the answer goes back there.
class TaskCancellationsController < ApplicationController
  require_second_factor "cancel_task"

  def task
    task = Task.includes(:host, :task_batch).find(params[:id])
    result = TaskCancellation.cancel_task!(task, operator: current_operator)
    if result.outcome == :finished
      redirect_back_or_to root_path, alert: "Not cancelled: task ##{task.id} already finished. It ended #{task.state.humanize(capitalize: false)} at #{utc(task.finished_at)}, before your request. A finished task cannot be cancelled."
    else
      redirect_back_or_to root_path, notice: task_notice(task, result)
    end
  end

  def batch
    batch = TaskBatch.find(params[:id])
    result = TaskCancellation.cancel_batch!(batch, operator: current_operator)
    redirect_back_or_to root_path, notice: batch_notice(batch, result)
  end

  private

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
