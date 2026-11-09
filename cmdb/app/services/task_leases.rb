# The time-based task changes (FR-3.2, P3-S05, AC-3.5, AC-3.8), run every minute by TaskExpiryJob and
# TaskLeaseJob. Every change is a Task transition, audited with the system as actor (P3-S07).
#
# expire!: a task still waiting at its expires_at is expired and never delivered. That covers a claimed task the
# agent never started, too: it goes back to the queue first (requeue), then expires, one audit entry each.
#
# lapse!: a lease that ran out.
# - claimed (the agent never said it had started): back to queued, so the next poll claims it again.
# - running, past its deadline plus the grace period (AgentTasks::RESULT_GRACE) with no result: timed_out if the
#   agent has been heard from since the deadline (a heartbeat or progress: it is there but did not report), or
#   failed with lease_expired if it has not (it stopped reporting, threat model L4). A result that arrives later is
#   kept beside the task as a late result and does not change its state (P3-S04).
#
# Safe to run twice at once and alongside polls (threat model L6): each task is taken with FOR UPDATE SKIP LOCKED
# in its own short transaction, so a task a poll, a start, a result, or the other run holds is left for the next
# run, and the transition checks the state again under the lock. A run handles at most MAX_PER_RUN tasks; the rest
# wait a minute.
module TaskLeases
  MAX_PER_RUN = 1_000

  module_function

  # Returns how many tasks expired.
  def expire!(now: Time.current)
    each_due(Task.where(state: %w[queued claimed]).where(expires_at: ..now).order(:expires_at, :id)) do |task|
      task.requeue!(actor: Audit::SYSTEM) if task.state == "claimed"
      task.expire!(actor: Audit::SYSTEM, now:)
    end
  end

  # Returns { "queued" => n, "timed_out" => n, "failed" => n }: what the lapsed tasks became.
  def lapse!(now: Time.current)
    counts = Hash.new(0)
    each_due(Task.where(state: %w[claimed running]).where(lease_expires_at: ..now).order(:lease_expires_at, :id)) do |task|
      if task.state == "claimed"
        task.requeue!(actor: Audit::SYSTEM)
      elsif heard_from_since_deadline?(task)
        task.time_out!(actor: Audit::SYSTEM, now:)
      else
        task.fail!(actor: Audit::SYSTEM, reason: "lease_expired", now:)
      end
      counts[task.state] += 1
    end
    counts
  end

  # Whether the task's agent made contact after the task's deadline: a heartbeat, or progress on the task.
  def heard_from_since_deadline?(task)
    deadline = task.started_at + task.timeout
    contact = [ task.host.last_seen_at, task.progress_reported_at ].compact.max
    contact.present? && contact > deadline
  end

  # Yields each due task, locked, in its own transaction; returns how many were yielded.
  def each_due(scope)
    count = 0
    while count < MAX_PER_RUN
      found = Task.transaction do
        task = scope.lock("FOR UPDATE SKIP LOCKED").first
        yield task if task
        task.present?
      end
      break unless found

      count += 1
    end
    count
  end

  private_class_method :heard_from_since_deadline?, :each_due
end
