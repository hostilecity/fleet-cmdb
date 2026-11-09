# What an agent does with its host's tasks through the agent API (FR-3.2, P3-S03, P3-S04): poll, start, report
# progress, and report the result. Api::V1::TasksController calls these inside one transaction, with the host row
# locked (AgentHostLock), so every task request of one host is serialised: two polls can never both claim, and a
# result and a start cannot cross. The task is always looked up through that host, so another host's task is
# never reached (the controller answers 404 for it).
#
# Poll (poll!): at most one task is claimed or running per host.
# - A running task blocks the host, and is never delivered again: the server knows it started.
# - A claimed task the agent has not started is delivered again, with a fresh lease, so an agent that restarted
#   gets it back and finds it in its ledger (P3-A02). Not after its expiry: it then goes back to the queue and
#   expires there at once (both audited with the system as actor, as the expiry job would), and the poll moves on,
#   so an expired claim never blocks its host (P3-S05).
# - Otherwise the oldest queued task is claimed. It is locked FOR UPDATE SKIP LOCKED in the same statement that
#   checks expires_at against the database clock (clock_timestamp()), so an expired task is never delivered
#   (AC-3.8, threat model L1), and expiry (P3-S05) cannot change it once it is locked.
# - The type and parameters are checked again against the current catalog and server policy before delivery
#   (Task#refusal_reason). A task that no longer passes is refused with its reason, the system as actor, and the
#   next one is tried.
#
# Start (start!): claimed becomes running, with a lease to the deadline plus a grace period. Anything else is
# left as it is and reported, so the agent runs a task only when the server says it is running. A start for a task
# that went back to the queue when its claim lapsed (threat model L2) answers run: false with state queued; the
# agent has not executed it, and the next poll claims it again (P3-S05).
#
# Cancel (cancel_directive): a running task of an interruptible type that an operator asked to cancel is named in
# the poll and progress responses until the agent reports its result (P3-S05). A task of any other type is never
# named: it runs to completion.
#
# Result (record_result!): applied to an open task through its transition (audited with the host as actor), or
# kept as a TaskLateResult when the server had already ended the task. The same result again is a duplicate and
# changes nothing; a different one, or one the task's state cannot take, is a conflict, audited and logged.
module AgentTasks
  # Until the agent starts a claimed task (FR-3.2); TaskLeases returns the task to the queue when it lapses.
  CLAIM_LEASE = 5.minutes
  # After the deadline, how long a running task may take to report before the lease lapses (TaskLeases then ends it
  # as timed_out, or failed with lease_expired if the agent has gone quiet).
  RESULT_GRACE = 5.minutes
  # Claim-time refusals one poll works through before it gives up and returns nothing.
  MAX_REFUSALS_PER_POLL = TaskBatches::MAX_HOSTS

  OUTCOMES = %w[succeeded failed timed_out cancelled refused].freeze
  # outcome => the Task transition that applies it.
  EVENTS = { "succeeded" => :succeed, "failed" => :fail, "timed_out" => :time_out, "cancelled" => :cancel, "refused" => :refuse }.freeze
  # outcome => the states an agent's result may end a task from. Narrower than Task::TRANSITIONS, which also
  # serves the operator and the server: an agent only ever holds a claimed or running task, so it can never
  # cancel or refuse a queued one, and it cancels only a running task of an interruptible type (DEC-14).
  AGENT_FROM = { "succeeded" => %w[running], "failed" => %w[claimed running], "timed_out" => %w[running],
                 "cancelled" => %w[running], "refused" => %w[claimed running] }.freeze
  # failed with not_run (P3-S05, threat model L2): the agent closes a task it holds in its ledger but never ran. Only
  # for a task that was never told to run: claimed, or queued again after this host's claim lapsed. Never for a
  # running one, which the server told to run.
  NOT_RUN_FROM = %w[queued claimed].freeze
  # The result details the server keeps (task-result.request); others are ignored.
  DETAIL_KEYS = %w[reboot_required services_needing_restart unit_active reports_sent].freeze

  # duplicate: the server already had this result; applied: it decided the task's state; conflict: refused, with
  # why ("different_result" or "state").
  Outcome = Data.define(:task, :duplicate, :applied, :conflict)

  module_function

  # The task to deliver to this host's poll, or nil. host must be locked (AgentHostLock).
  def poll!(host:, now: Time.current)
    return nil if host.tasks.exists?(state: "running")

    if (claimed = host.tasks.where(state: "claimed").lock.first)
      if host.tasks.where(id: claimed.id).where("expires_at > clock_timestamp()").exists?
        unless refuse_if_invalid(claimed)
          claimed.renew_lease!(lease_expires_at: now + CLAIM_LEASE)
          return claimed
        end
      else
        claimed.requeue!(actor: Audit::SYSTEM).expire!(actor: Audit::SYSTEM, now:)
      end
    end

    MAX_REFUSALS_PER_POLL.times do
      task = host.tasks.where(state: "queued").where("expires_at > clock_timestamp()").order(:created_at, :id).lock("FOR UPDATE SKIP LOCKED").first
      return nil unless task
      next if refuse_if_invalid(task)

      return task.claim!(actor: host, lease_expires_at: now + CLAIM_LEASE, now:)
    end
    nil
  end

  # The poll payload (task-poll.response): the id, type, parameters, deadline, and catalog version. Nothing else.
  def delivery(task)
    { id: task.uuid, type: task.task_type, parameters: task.parameters, timeout_seconds: task.timeout_seconds,
      catalog_version: TaskCatalog.current.version }
  end

  # The cancel directive for the poll and progress responses ({ id: }), or nil: the host's running task, if an
  # operator asked to cancel it and its type is interruptible.
  def cancel_directive(host)
    task = host.tasks.where(state: "running").where.not(cancel_requested_at: nil).first
    task&.interruptible? ? { id: task.uuid } : nil
  end

  # Whether this host's next poll would get a task: the heartbeat's tasks_available directive. One query.
  def available?(host_id:)
    Task.where(host_id:, state: %w[queued claimed]).where("expires_at > clock_timestamp()")
        .where("NOT EXISTS (?)", Task.select(1).where(host_id:, state: "running")).exists?
  end

  # The agent recorded the task as started and asks to run it. Returns the task in its state now.
  def start!(host:, task:, agent_started_at:, now: Time.current)
    task.lock!
    return task unless task.state == "claimed"
    return task if refuse_if_invalid(task)

    task.start!(actor: host, lease_expires_at: now + task.timeout + RESULT_GRACE, agent_started_at:, now:)
  end

  # payload: a task-result.request that validated against its schema.
  def record_result!(host:, task:, payload:, now: Time.current)
    task.lock!
    digest = result_digest(payload)
    previous = task.agent_result? ? task.result_digest : task.late_result&.digest
    if previous
      return conflict!(host, task, payload, "different_result") unless previous == digest

      return Outcome.new(task:, duplicate: true, applied: task.agent_result?, conflict: nil)
    end
    return keep_late!(host, task, payload, digest, now) if task.terminal?
    return conflict!(host, task, payload, "state") unless takes?(task, payload)

    apply!(host, task, payload, digest, now)
  end

  # The fields that make one result the same as another, hashed: everything but report_id and the versions. The
  # raw output is hashed on its own, so invalid UTF-8 in it cannot break the digest.
  def result_digest(payload)
    fields = {
      "outcome" => payload["outcome"], "reason" => payload["reason"], "exit_status" => payload["exit_status"],
      "started_at" => payload["started_at"], "finished_at" => payload["finished_at"], "details" => details(payload),
      "output" => payload["output"] && OpenSSL::Digest::SHA256.hexdigest(payload["output"].b),
      "output_truncated" => payload["output_truncated"] || false
    }
    OpenSSL::Digest::SHA256.hexdigest(JSON.generate(fields))
  end

  def details(payload)
    kept = payload["details"].is_a?(Hash) ? payload["details"].slice(*DETAIL_KEYS).compact : {}
    kept.presence
  end

  def refuse_if_invalid(task)
    reason = task.refusal_reason or return false
    task.refuse!(actor: Audit::SYSTEM, reason:)
    true
  end

  def takes?(task, payload)
    outcome = payload["outcome"]
    if outcome == "failed" && payload["reason"] == "not_run"
      return NOT_RUN_FROM.include?(task.state) && (task.state == "claimed" || claimed_by?(task, task.host))
    end
    return false unless AGENT_FROM.fetch(outcome).include?(task.state)

    outcome != "cancelled" || task.interruptible?
  end

  # Whether this host ever claimed the task: a queued task it may close as not_run went back to the queue from it.
  def claimed_by?(task, host)
    AuditEntry.where(action: Audit::Actions::TASK_CLAIMED, target_type: "Task", target_id: task.id, actor_type: "host", actor_id: host.id).exists?
  end

  def apply!(host, task, payload, digest, now)
    output = TaskOutput.sanitize(payload["output"], limit: TaskSettings.output_limit_bytes)
    result = {
      exit_status: payload["exit_status"], output: output.text, output_truncated: output.truncated || payload["output_truncated"] || false,
      agent_started_at: agent_time(payload["started_at"]), agent_finished_at: agent_time(payload["finished_at"]),
      report: { result_report_id: payload["report_id"], result_digest: digest, result_received_at: now, result_details: details(payload) },
      now:
    }
    result[:reason] = payload["reason"] if %w[failed refused].include?(payload["outcome"])
    task.public_send(:"#{EVENTS.fetch(payload['outcome'])}!", actor: host, **result)
    Outcome.new(task:, duplicate: false, applied: true, conflict: nil)
  end

  def keep_late!(host, task, payload, digest, now)
    output = TaskOutput.sanitize(payload["output"], limit: TaskSettings.output_limit_bytes)
    task.create_late_result!(
      report_id: payload["report_id"], outcome: payload["outcome"], reason: payload["reason"], exit_status: payload["exit_status"],
      agent_started_at: agent_time(payload["started_at"]), agent_finished_at: agent_time(payload["finished_at"]),
      details: details(payload), output: output.text, output_truncated: output.truncated || payload["output_truncated"] || false,
      digest:, received_at: now, created_at: now
    )
    Audit.record(actor: host, action: Audit::Actions::TASK_LATE_RESULT, target: task,
                 changes: { "outcome" => payload["outcome"], "reason" => payload["reason"], "exit_status" => payload["exit_status"], "state" => task.state }.compact)
    Outcome.new(task:, duplicate: false, applied: false, conflict: nil)
  end

  # Audited, and logged without the output, so a disagreement between the agent and the server can be found.
  def conflict!(host, task, payload, why)
    Audit.record(actor: host, action: Audit::Actions::TASK_RESULT_CONFLICT, target: task,
                 changes: { "outcome" => payload["outcome"], "reason" => payload["reason"], "state" => task.state, "conflict" => why }.compact)
    Rails.logger.warn("[agent_api] task #{task.uuid} result refused (#{why}): #{payload['outcome']} for a #{task.state} task")
    Outcome.new(task:, duplicate: false, applied: false, conflict: why)
  end

  def agent_time(value) = value && Time.iso8601(value)

  private_class_method :refuse_if_invalid, :takes?, :claimed_by?, :apply!, :keep_late!, :conflict!, :agent_time, :details
end
