require "rails_helper"

# P3-S07: the task audit trail, walked through the code paths that make each change (the agent API services, the
# jobs, cancellation, and the settings), not the model alone. Every state transition writes exactly one entry with
# the right actor: the operator for what an operator does, the host for what its agent does, the system for what
# time does. No entry holds task output, a code, or a secret, and retention never prunes them (DEC-07, NFR-2).
RSpec.describe "Task audit trail" do
  let(:operator) { create(:operator) }
  let(:host) { task_host(last_seen_at: 1.hour.ago) }
  let(:output) { "SECRET-LOOKING OUTPUT <b>do not copy</b>" }

  def new_task(type: "refresh_reports") = create_task_batch([ host ], type:, operator:, parameters: type == "restart_service" ? { "service" => "nginx.service" } : {}).tasks.sole

  def poll = Task.transaction { AgentTasks.poll!(host: Host.lock.find(host.id)) }

  def start(task) = Task.transaction { AgentTasks.start!(host:, task: task.reload, agent_started_at: Time.current) }

  def report(task, outcome, **fields)
    payload = ApiContract.example("task-result.request", "succeeded")
                         .merge("report_id" => SecureRandom.uuid, "outcome" => outcome, "output" => output, "reason" => nil, "exit_status" => nil, "details" => nil)
                         .merge(fields.stringify_keys)
    Task.transaction { AgentTasks.record_result!(host:, task: task.reload, payload:) }
  end

  # Each task's entries since `since`, as [action, actor_type].
  def trail(task, since:) = AuditEntry.where(target_type: "Task", target_id: task.id).where("id > ?", since).order(:id).pluck(:action, :actor_type)

  def mark = AuditEntry.maximum(:id).to_i

  def step(task)
    before = mark
    yield
    trail(task, since: before)
  end

  it "writes one entry per transition, with the right actor, through every path (checklist)" do
    allow_restart("nginx.service")
    a = Audit::Actions

    created = mark
    task = new_task
    expect(trail(task, since: created)).to eq([ [ a::TASK_CREATED, "operator" ] ])
    expect(AuditEntry.where(action: a::TASK_BATCH_CREATED, target_id: task.task_batch_id).pluck(:actor_type)).to eq([ "operator" ])

    expect(step(task) { poll }).to eq([ [ a::TASK_CLAIMED, "host" ] ])
    expect(step(task) { poll }).to eq([]) # delivered again, not claimed again
    expect(step(task) { travel(6.minutes) { TaskLeases.lapse! } }).to eq([ [ a::TASK_REQUEUED, "system" ] ])
    expect(step(task) { poll }).to eq([ [ a::TASK_CLAIMED, "host" ] ])
    expect(step(task) { start(task) }).to eq([ [ a::TASK_STARTED, "host" ] ])
    expect(step(task) { start(task) }).to eq([]) # a repeated start
    expect(step(task) { TaskCancellation.cancel_task!(task, operator:) }).to eq([ [ a::TASK_CANCEL_REQUESTED, "operator" ] ])
    expect(step(task) { report(task, "cancelled") }).to eq([ [ a::TASK_CANCELLED, "host" ] ])
    expect(step(task) { report(task, "cancelled") }).to eq([]) # a duplicate result

    succeeded = new_task
    poll
    start(succeeded)
    expect(step(succeeded) { report(succeeded, "succeeded", exit_status: 0) }).to eq([ [ a::TASK_SUCCEEDED, "host" ] ])

    failed = new_task
    poll
    expect(step(failed) { report(failed, "refused", reason: "not_enabled_locally") }).to eq([ [ a::TASK_REFUSED, "host" ] ])

    cancelled = new_task
    expect(step(cancelled) { TaskCancellation.cancel_task!(cancelled, operator:) }).to eq([ [ a::TASK_CANCELLED, "operator" ] ])

    expired = new_task
    expect(step(expired) { travel(25.hours) { TaskLeases.expire! } }).to eq([ [ a::TASK_EXPIRED, "system" ] ])

    expired_claim = new_task
    poll
    expect(step(expired_claim) { travel(25.hours) { TaskLeases.expire! } }).to eq([ [ a::TASK_REQUEUED, "system" ], [ a::TASK_EXPIRED, "system" ] ])

    lapsed = new_task
    poll
    start(lapsed)
    expect(step(lapsed) { travel(16.minutes) { TaskLeases.lapse! } }).to eq([ [ a::TASK_FAILED, "system" ] ]) # lease_expired
    expect(step(lapsed) { report(lapsed, "succeeded", exit_status: 0) }).to eq([ [ a::TASK_LATE_RESULT, "host" ] ])

    timed_out = new_task
    poll
    start(timed_out)
    travel(16.minutes) do
      host.update_columns(last_seen_at: Time.current)
      expect(step(timed_out) { TaskLeases.lapse! }).to eq([ [ a::TASK_TIMED_OUT, "system" ] ])
    end

    refused_at_claim = new_task(type: "restart_service")
    TaskAllowedService.delete_all
    expect(step(refused_at_claim) { poll }).to eq([ [ a::TASK_REFUSED, "system" ] ])

    # Settings changes: the operator, with before and after.
    entry = TaskSettings.add_service!(service: "chrony.service", tag: nil, actor: operator)
    TaskSettings.remove_service!(entry.id, actor: operator)
    TaskSettings.update_limits!({ "poll_seconds" => "60" }, actor: operator)
    settings = AuditEntry.where(action: [ a::TASK_SETTING_SERVICE_ADDED, a::TASK_SETTING_SERVICE_REMOVED, a::TASK_SETTING_LIMITS_CHANGED ]).order(:id)
    expect(settings.pluck(:action, :actor_type)).to eq([ [ a::TASK_SETTING_SERVICE_ADDED, "operator" ], [ a::TASK_SETTING_SERVICE_REMOVED, "operator" ], [ a::TASK_SETTING_LIMITS_CHANGED, "operator" ] ])
    expect(settings.map(&:changeset)).to all(satisfy { |changes| changes.values.any? { |value| value.is_a?(Array) && value.size == 2 } })

    # Every transition the state machine has was walked above.
    walked = AuditEntry.where(target_type: "Task").distinct.pluck(:action)
    expect(walked).to include(*Task::TRANSITIONS.values.map { |rule| rule[:action] })

    # No entry holds output.
    expect(AuditEntry.where("changeset::text LIKE ?", "%SECRET-LOOKING%")).to be_empty
    expect(AuditEntry.where(target_type: "Task").pluck(:changeset).flat_map(&:keys).uniq).not_to include("output")
  end

  it "keeps task audit entries and tasks however old: retention never prunes them (DEC-07, NFR-2)" do
    task = new_task
    task.expire!(actor: Audit::SYSTEM)
    count = AuditEntry.count
    Retention.prune!(now: 20.years.from_now)
    expect(AuditEntry.count).to eq(count)
    expect(Task.exists?(task.id)).to be(true)
    expect(Retention.targets.map { |target| target.model.table_name }).not_to include("tasks", "task_batches", "task_late_results", "audit_entries")
  end
end
