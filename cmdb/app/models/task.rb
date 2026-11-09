# One task for one host (FR-3.2, P3-S02): a type from the task catalog and parameters that validated against that
# type's closed schema (FR-3.1, P3-S01). There is no attribute that can hold a command, a script, or an executable
# name, and the type, parameters, host, batch, expiry, and timeout never change after creation (the tasks_guard
# database trigger refuses it). Tasks are created only by TaskBatches.create!, one per targeted host, so each
# succeeds or fails on its own.
#
# State changes only through the transition methods below, which follow TRANSITIONS, raise InvalidTransition for
# anything else, and write exactly one audit entry with the given actor in the same transaction (P3-S07). A task
# in a terminal state never changes again: the record is read-only, and tasks_guard refuses it too. Times the
# agent reports (agent_started_at, agent_finished_at) are kept apart from the server's own (claimed_at,
# started_at, finished_at), which are the only ones used for leases and timeouts.
class Task < ApplicationRecord
  class InvalidTransition < StandardError; end

  STATES = %w[queued claimed running succeeded failed timed_out cancelled refused expired].freeze
  TERMINAL_STATES = %w[succeeded failed timed_out cancelled refused expired].freeze
  OPEN_STATES = (STATES - TERMINAL_STATES).freeze

  # Why a task failed. nonzero_exit: the task ran and exited unsuccessfully (exit_status says how); interrupted:
  # the agent stopped mid-task, for example on shutdown, and reports it on its next start (FR-3.2, FR-3.3);
  # lease_expired: the agent said it had started and then stopped reporting (FR-3.2); lock_timeout: the package
  # manager's lock stayed held (DEC-16); agent_error: the agent could not run the task for a reason of its own.
  FAILED_REASONS = %w[nonzero_exit interrupted lease_expired lock_timeout agent_error].freeze
  # Why a task was refused, with nothing run (AC-3.1, AC-3.9). The server refuses at claim time when the task no
  # longer validates or is no longer allowed; the agent refuses with its own checks.
  # unknown_type, invalid_params: the type or parameters fail the catalog, on either side;
  # not_supported: the host no longer reports supporting the type; not_enabled_locally: the VM's configuration
  # does not enable the type (DEC-14); not_allowed_locally: the service is not on the VM's own allowlist;
  # not_allowed_on_server: it is no longer on the server's allowlist; protected_service: the service is one that
  # is always refused (DEC-15).
  REFUSED_REASONS = %w[unknown_type invalid_params not_supported not_enabled_locally not_allowed_locally
                       not_allowed_on_server protected_service].freeze
  REASONS = { "failed" => FAILED_REASONS, "refused" => REFUSED_REASONS }.freeze

  # The attributes an agent's result sets beside the outcome (P3-S04).
  REPORT_ATTRIBUTES = %i[result_report_id result_digest result_received_at result_details].freeze

  # The hard limit on stored output, whatever the configured output limit (P3-S04); the database checks it too.
  MAX_OUTPUT_BYTES = 1.megabyte

  # The transition table: event => allowed source states, target state, audit action. tasks_guard holds the
  # same pairs. A claimed task the agent never started goes back to the queue when its lease lapses (requeue);
  # a started one fails with lease_expired instead (FR-3.2). A running task is cancelled only if its type is
  # interruptible (DEC-14); otherwise it runs to the end.
  TRANSITIONS = {
    claim: { from: %w[queued], to: "claimed", action: Audit::Actions::TASK_CLAIMED },
    requeue: { from: %w[claimed], to: "queued", action: Audit::Actions::TASK_REQUEUED },
    start: { from: %w[claimed], to: "running", action: Audit::Actions::TASK_STARTED },
    succeed: { from: %w[running], to: "succeeded", action: Audit::Actions::TASK_SUCCEEDED },
    fail: { from: %w[claimed running], to: "failed", action: Audit::Actions::TASK_FAILED },
    time_out: { from: %w[running], to: "timed_out", action: Audit::Actions::TASK_TIMED_OUT },
    cancel: { from: %w[queued claimed running], to: "cancelled", action: Audit::Actions::TASK_CANCELLED },
    refuse: { from: %w[queued claimed running], to: "refused", action: Audit::Actions::TASK_REFUSED },
    expire: { from: %w[queued], to: "expired", action: Audit::Actions::TASK_EXPIRED }
  }.freeze

  belongs_to :task_batch
  belongs_to :host
  belongs_to :cancel_requested_by, class_name: "Operator", optional: true
  # A result that arrived after the server had ended the task itself (P3-S04): kept beside it, never applied.
  has_one :late_result, class_name: "TaskLateResult", dependent: :restrict_with_exception

  attr_readonly :uuid, :task_batch_id, :host_id, :task_type, :parameters, :expires_at, :timeout_seconds

  validates :state, inclusion: { in: STATES }
  validates :task_type, presence: true
  validate :reason_fits_state
  validate :output_within_limit

  before_create :require_queued_state
  before_update :require_transition_for_state_change
  before_destroy { raise ActiveRecord::ReadOnlyRecord, "tasks are never deleted" }

  scope :open_now, -> { where(state: OPEN_STATES) }
  scope :terminal, -> { where(state: TERMINAL_STATES) }

  def terminal? = TERMINAL_STATES.include?(state_in_database)

  # Finished tasks are read-only, so nothing can rewrite what happened.
  def readonly? = super || (persisted? && terminal?)

  # The catalog entry for this task's type, or nil when the catalog no longer has it.
  def catalog_entry = TaskCatalog.current.type?(task_type) ? TaskCatalog.current.entry(task_type) : nil

  def interruptible? = catalog_entry&.interruptible || false

  def timeout = timeout_seconds.seconds

  def expired_by?(time) = state == "queued" && expires_at <= time

  # Why this task should be refused if it were delivered now, as a Task reason, or nil when it may run: it is
  # checked against the current catalog and server policy, so a catalog or allowlist change since creation is
  # caught at claim time (P3-S01, P3-S03, P3-S06). A restart is checked against the allowlist entries for this
  # host's tags as they are now.
  def refusal_reason = TaskPolicy.refusal(task_type, parameters, host:)&.reason

  # queued -> claimed: an agent's poll claimed the task until lease_expires_at.
  def claim!(actor:, lease_expires_at:, now: Time.current)
    transition!(:claim, actor:, attributes: { claimed_at: now, lease_expires_at: })
  end

  # claimed -> queued: the lease lapsed before the agent said it had started, so the task waits again.
  def requeue!(actor:) = transition!(:requeue, actor:, attributes: { claimed_at: nil, lease_expires_at: nil })

  # claimed -> running: the agent recorded the task as started (P3-A02) and said so.
  def start!(actor:, lease_expires_at:, agent_started_at: nil, now: Time.current)
    transition!(:start, actor:, attributes: { started_at: now, lease_expires_at:, agent_started_at: })
  end

  # running -> succeeded.
  def succeed!(actor:, **result) = finish!(:succeed, actor:, **result)

  # claimed or running -> failed, with a reason from FAILED_REASONS.
  def fail!(actor:, reason:, **result) = finish!(:fail, actor:, reason:, **result)

  # running -> timed_out: past its timeout, terminated by the agent or given up on by the server (FR-3.2).
  def time_out!(actor:, **result) = finish!(:time_out, actor:, **result)

  # queued, claimed, or running -> cancelled. A running task can be cancelled only if its type is interruptible.
  def cancel!(actor:, **result) = finish!(:cancel, actor:, **result)

  # queued, claimed, or running -> refused, with a reason from REFUSED_REASONS. Nothing was run.
  def refuse!(actor:, reason:, **result) = finish!(:refuse, actor:, reason:, **result)

  # queued -> expired: still waiting at its expiry, so it is never delivered (FR-3.2, AC-3.8).
  def expire!(actor:, now: Time.current) = finish!(:expire, actor:, now:)

  # Whether an agent's result decided how this task ended (P3-S04). A terminal task without one was ended by the
  # server: expired, timed out, lease expired, cancelled, or refused at claim.
  def agent_result? = result_digest.present?

  # Whether an operator asked to cancel this task while it was running (P3-S05). The task keeps its real state: an
  # interruptible one is stopped by its agent, which then reports cancelled; any other runs to completion.
  def cancel_requested? = cancel_requested_at.present?

  # Records an operator's request to cancel a running task (P3-S05, mockup cancel.html), audited as
  # task.cancel_requested. Not a state transition: the state changes only when the agent reports the result. Returns
  # false, recording nothing, when a request was already recorded or the task is not running (a queued or claimed task
  # is cancelled at once instead). tasks_guard keeps the request as recorded.
  def request_cancel!(operator:, now: Time.current)
    transaction(requires_new: true) do
      lock!
      next false unless state == "running" && !cancel_requested?

      update!(cancel_requested_at: now, cancel_requested_by: operator)
      Audit.record(actor: operator, action: Audit::Actions::TASK_CANCEL_REQUESTED, target: self,
                   changes: { "cancel_requested" => [ false, true ], "effect" => interruptible? ? "stop" : "runs_to_completion" })
      true
    end
  end

  # A running task's progress as the agent reports it (P3-S04): ignored once the task is not running.
  def record_progress!(percent:, now: Time.current)
    with_lock { update!(progress_percent: percent, progress_reported_at: now) if state == "running" }
    self
  end

  # A claimed task delivered again to its host's poll (P3-S03): the lease starts over. Not a transition, so no
  # audit entry; the claim was audited.
  def renew_lease!(lease_expires_at:)
    raise InvalidTransition, "only a claimed task's lease is renewed" unless state == "claimed"

    update!(lease_expires_at:)
  end

  # update_column(s) skip callbacks, so guard the state here too. Bulk paths (update_all) are stopped by tasks_guard.
  def update_columns(attributes)
    if attributes.to_h.stringify_keys.key?("state") && !@transitioning
      raise InvalidTransition, "task state changes only through the transition methods"
    end

    super
  end

  private

  # report: what identifies an agent's result (P3-S04, AgentTasks.record_result!): result_report_id, result_digest,
  # result_received_at, and result_details. Absent when the server ends the task itself.
  def finish!(event, actor:, reason: nil, exit_status: nil, output: nil, output_truncated: false,
              agent_started_at: nil, agent_finished_at: nil, report: {}, now: Time.current)
    attributes = { finished_at: now, reason:, exit_status:, output:, output_truncated:, lease_expires_at: nil }
    attributes[:agent_started_at] = agent_started_at if agent_started_at
    attributes[:agent_finished_at] = agent_finished_at if agent_finished_at
    attributes.merge!(report.to_h.slice(*REPORT_ATTRIBUTES))
    transition!(event, actor:, attributes:)
  end

  def transition!(event, actor:, attributes:)
    rule = TRANSITIONS.fetch(event)
    # requires_new: a savepoint, so a failed audit write rolls the change back even when the caller rescues
    # the error inside its own transaction.
    transaction(requires_new: true) do
      lock!
      raise InvalidTransition, "cannot #{event.to_s.tr('_', ' ')} a #{state} task" unless rule[:from].include?(state)
      if event == :cancel && state == "running" && !interruptible?
        raise InvalidTransition, "cannot cancel a running #{task_type} task: its type is not interruptible"
      end

      before = state
      @transitioning = true
      update!(attributes.merge(state: rule[:to]))
      changes = { "state" => [ before, state ] }
      changes["reason"] = reason if reason
      changes["exit_status"] = exit_status unless exit_status.nil?
      Audit.record(actor:, action: rule[:action], target: self, changes:)
    ensure
      @transitioning = false
    end
    self
  end

  def require_queued_state
    raise InvalidTransition, "new tasks start queued" unless state == "queued"
  end

  def require_transition_for_state_change
    return unless state_changed? && !@transitioning

    raise InvalidTransition, "task state changes only through the transition methods"
  end

  def reason_fits_state
    allowed = REASONS[state]
    if allowed.nil?
      errors.add(:reason, "must be empty for a #{state} task") unless reason.nil?
    elsif !allowed.include?(reason)
      errors.add(:reason, "must be one of #{allowed.join(', ')} for a #{state} task")
    end
  end

  def output_within_limit
    errors.add(:output, "is longer than #{MAX_OUTPUT_BYTES} bytes") if output && output.bytesize > MAX_OUTPUT_BYTES
  end
end
