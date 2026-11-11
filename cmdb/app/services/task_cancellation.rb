# An operator cancelling a task or the rest of a batch (FR-3.2, P3-S05, DEC-14; mockups cancel.html and
# batch-partial.html, owner decisions Q17 and Q23). Any operator may cancel any task; the dashboard asks for the
# second factor first (cancel_task). Nothing is ever undone: a finished task is not changed.
#
# - queued or claimed: cancelled now, with the operator as actor. A queued task is never delivered; a claimed one
#   the agent has not started is refused when its start arrives (run: false), and the agent drops it (threat model
#   L3).
# - running, interruptible: the request is recorded (task.cancel_requested) and the cancel directive goes to the
#   agent in its next poll or progress response; the task becomes cancelled when the agent reports it stopped.
# - running, not interruptible: the request is recorded beside its real state and the task runs to completion.
#   No task of its batch that has not started will start: those are cancelled now (Q17).
#
# Tasks are locked in id order, so two cancels of one batch cannot deadlock, and each transition checks the state
# again under the lock, so a task that a poll claimed or an agent started a moment ago is handled by its new state.
module TaskCancellation
  UNSTARTED = %w[queued claimed].freeze

  # What a cancel did. outcome, for a single task: :cancelled (it was queued or claimed), :stop_requested (running,
  # interruptible), :cancel_requested (running, not interruptible), :already_requested, :finished (nothing done), or
  # :changed (nothing done: the task started, or went back to the queue, since the confirmation the operator saw).
  # cancelled: the tasks cancelled now, including others of the batch; stopping and running_on: the running tasks
  # whose request was recorded, by whether they will stop; finished: tasks left as they were because they had ended.
  Result = Data.define(:outcome, :cancelled, :stopping, :running_on, :finished)

  module_function

  # seen: "unstarted" or "running", the state the operator's confirmation described (P3-DASH-TASKS). When given and
  # the task, under the lock, is no longer in it, nothing is done: a cancel of a waiting task must never become a
  # cancel of the rest of its batch because the task started in between. Without seen (no confirmation page), the
  # cancel does what the task's state allows now.
  def cancel_task!(task, operator:, now: Time.current, seen: nil)
    Task.transaction(requires_new: true) do
      lock_batch(task.task_batch)
      task.reload
      if task.terminal?
        result(:finished, finished: [ task ])
      elsif seen && seen != (UNSTARTED.include?(task.state) ? "unstarted" : "running")
        result(:changed)
      elsif UNSTARTED.include?(task.state)
        task.cancel!(actor: operator, now:)
        result(:cancelled, cancelled: [ task ])
      elsif task.cancel_requested?
        result(:already_requested)
      elsif task.interruptible?
        task.request_cancel!(operator:, now:)
        result(:stop_requested, stopping: [ task ])
      else
        task.request_cancel!(operator:, now:)
        result(:cancel_requested, running_on: [ task ], cancelled: cancel_unstarted!(task.task_batch, operator, now, except: task))
      end
    end
  end

  # Cancels everything in the batch that has not ended: unstarted tasks now, running ones by request.
  def cancel_batch!(batch, operator:, now: Time.current)
    Task.transaction(requires_new: true) do
      tasks = lock_batch(batch)
      cancelled = []
      stopping = []
      running_on = []
      tasks.each do |task|
        if UNSTARTED.include?(task.state)
          task.cancel!(actor: operator, now:)
          cancelled << task
        elsif task.state == "running" && task.request_cancel!(operator:, now:)
          (task.interruptible? ? stopping : running_on) << task
        end
      end
      result(:batch, cancelled:, stopping:, running_on:, finished: tasks.select(&:terminal?) - cancelled)
    end
  end

  # Every task of the batch, locked in id order (at most 25).
  def lock_batch(batch) = batch.tasks.order(:id).lock.to_a

  def cancel_unstarted!(batch, operator, now, except:)
    batch.tasks.where(state: UNSTARTED).where.not(id: except.id).order(:id).map { |task| task.cancel!(actor: operator, now:) }
  end

  def result(outcome, cancelled: [], stopping: [], running_on: [], finished: []) = Result.new(outcome:, cancelled:, stopping:, running_on:, finished:)

  private_class_method :lock_batch, :cancel_unstarted!, :result
end
