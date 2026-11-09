require "rails_helper"

# P3-S02: the task state machine. Every legal transition has an example below, generated from Task::TRANSITIONS;
# every other (event, state) pair raises; terminal states never change, in the model or in the database.
RSpec.describe Task do
  let(:operator) { create(:operator) }
  let(:host) { task_host }
  let(:lease) { 5.minutes.from_now }

  # The arguments each event needs.
  def event_arguments(event)
    {
      claim: { lease_expires_at: lease },
      requeue: {},
      start: { lease_expires_at: lease, agent_started_at: 1.minute.ago },
      succeed: { exit_status: 0, output: "done", agent_finished_at: Time.current },
      fail: { reason: "interrupted" },
      time_out: { output: "partial", output_truncated: true },
      cancel: {},
      refuse: { reason: "invalid_params" },
      expire: {}
    }.fetch(event)
  end

  # How to reach each state from queued, through the transition methods.
  def paths
    {
      "queued" => [], "claimed" => %i[claim], "running" => %i[claim start], "succeeded" => %i[claim start succeed],
      "failed" => %i[claim start fail], "timed_out" => %i[claim start time_out], "cancelled" => %i[cancel],
      "refused" => %i[refuse], "expired" => %i[expire]
    }
  end

  def fire(task, event, actor: host) = task.public_send(:"#{event}!", actor:, **event_arguments(event))

  def task_in(state, type: "refresh_reports")
    task = create_task(host, type:, operator:)
    paths.fetch(state).each { |event| fire(task, event) }
    task
  end

  def in_savepoint(&) = Task.transaction(requires_new: true, &)

  it "lists every state in the transition table and reaches every state" do
    expect(paths.keys).to match_array(Task::STATES)
    expect(Task::TRANSITIONS.values.flat_map { |rule| rule[:from] + [ rule[:to] ] }.uniq).to match_array(Task::STATES)
    expect(Task::TRANSITIONS.values.flat_map { |rule| rule[:from] } & Task::TERMINAL_STATES).to eq([]) # terminal states have no way out
  end

  Task::TRANSITIONS.each do |event, rule|
    rule[:from].each do |from|
      it "#{event}: #{from} -> #{rule[:to]}, audited once with the actor" do
        task = task_in(from)
        expect { fire(task, event) }.to change { AuditEntry.where(action: rule[:action], target_type: "Task", target_id: task.id).count }.by(1)
        expect(task.reload.state).to eq(rule[:to])
        entry = AuditEntry.where(target_type: "Task", target_id: task.id).order(:id).last
        expect(entry.attributes.slice("actor_type", "actor_id")).to eq("actor_type" => "host", "actor_id" => host.id)
        expect(entry.changeset["state"]).to eq([ from, rule[:to] ])
      end
    end

    (Task::STATES - rule[:from]).each do |from|
      it "#{event}: raises from #{from} and changes nothing" do
        task = task_in(from)
        expect { fire(task, event) }.to raise_error(Task::InvalidTransition, /cannot #{event.to_s.tr('_', ' ')} a #{from} task/)
        expect(task.reload.state).to eq(from)
      end
    end
  end

  describe "what each transition records" do
    it "keeps the server's times apart from the agent's, and holds the lease only while open" do
      freeze_time do
        task = task_in("queued")
        task.claim!(actor: host, lease_expires_at: 2.minutes.from_now)
        expect(task.reload.attributes.slice("claimed_at", "lease_expires_at")).to eq("claimed_at" => Time.current, "lease_expires_at" => 2.minutes.from_now)
        task.requeue!(actor: Audit::SYSTEM)
        expect(task.reload.attributes.slice("claimed_at", "lease_expires_at")).to eq("claimed_at" => nil, "lease_expires_at" => nil)
        task.claim!(actor: host, lease_expires_at: 2.minutes.from_now)
        task.start!(actor: host, lease_expires_at: 10.minutes.from_now, agent_started_at: 1.hour.ago)
        expect(task.reload.attributes.slice("started_at", "agent_started_at", "lease_expires_at"))
          .to eq("started_at" => Time.current, "agent_started_at" => 1.hour.ago, "lease_expires_at" => 10.minutes.from_now)
        task.fail!(actor: host, reason: "nonzero_exit", exit_status: 100, output: "E: broken", agent_finished_at: 59.minutes.ago)
        expect(task.reload.attributes.slice("state", "reason", "exit_status", "output", "finished_at", "agent_started_at", "agent_finished_at", "lease_expires_at"))
          .to eq("state" => "failed", "reason" => "nonzero_exit", "exit_status" => 100, "output" => "E: broken", "finished_at" => Time.current,
                 "agent_started_at" => 1.hour.ago, "agent_finished_at" => 59.minutes.ago, "lease_expires_at" => nil)
        expect(AuditEntry.where(target_type: "Task", target_id: task.id).order(:id).last.changeset)
          .to eq("state" => %w[running failed], "reason" => "nonzero_exit", "exit_status" => 100)
      end
    end

    it "never puts output in the audit log" do
      task = task_in("running")
      task.succeed!(actor: host, exit_status: 0, output: "secret-looking output")
      expect(AuditEntry.where(target_type: "Task", target_id: task.id).map(&:changeset).to_json).not_to include("secret-looking")
    end

    it "takes the actor it is given: the system for time-based changes" do
      task = task_in("queued")
      task.expire!(actor: Audit::SYSTEM)
      expect(AuditEntry.where(action: "task.expired", target_id: task.id).sole.actor_type).to eq("system")
    end
  end

  describe "cancellation of a running task (DEC-14)" do
    it "is refused when the type is not interruptible, and allowed when it is" do
      running = task_in("running", type: "apply_package_updates")
      expect { running.cancel!(actor: operator) }.to raise_error(Task::InvalidTransition, /not interruptible/)
      expect(running.reload.state).to eq("running")
      expect(task_in("running").cancel!(actor: operator).reload.state).to eq("cancelled")
      expect(task_in("claimed", type: "apply_package_updates").cancel!(actor: operator).reload.state).to eq("cancelled")
    end

    it "treats a type the catalog no longer has as not interruptible" do
      task = task_in("running")
      stub_catalog_without("refresh_reports")
      expect(task.catalog_entry).to be_nil
      expect { task.cancel!(actor: operator) }.to raise_error(Task::InvalidTransition)
    end
  end

  describe "reasons" do
    it "requires a listed reason for failed and refused, and none otherwise" do
      expect { task_in("running").fail!(actor: host, reason: "it broke") }.to raise_error(ActiveRecord::RecordInvalid, /must be one of nonzero_exit/)
      expect { task_in("queued").refuse!(actor: host, reason: "interrupted") }.to raise_error(ActiveRecord::RecordInvalid, /must be one of unknown_type/)
      expect { task_in("running").succeed!(actor: host, reason: "interrupted") }.to raise_error(ActiveRecord::RecordInvalid, /must be empty for a succeeded task/)
    end

    it "keeps the reason lists disjoint and short enough for the column" do
      expect(Task::FAILED_REASONS & Task::REFUSED_REASONS).to eq([])
      expect((Task::FAILED_REASONS + Task::REFUSED_REASONS).map(&:length).max).to be <= 32
    end
  end

  describe "immutability" do
    it "makes a terminal task read-only" do
      task = task_in("succeeded")
      expect(task).to be_readonly
      expect { task.update!(output: "rewritten") }.to raise_error(ActiveRecord::ReadOnlyRecord)
    end

    it "never changes what a task is" do
      task = task_in("queued")
      expect { task.parameters = { "service" => "x.service" } }.to raise_error(ActiveRecord::ReadonlyAttributeError)
      expect { task.host_id = create(:host).id }.to raise_error(ActiveRecord::ReadonlyAttributeError)
    end

    it "changes state only through the transition methods" do
      task = task_in("queued")
      expect { task.update!(state: "succeeded") }.to raise_error(Task::InvalidTransition, /only through the transition methods/)
      expect { task.update_columns(state: "running") }.to raise_error(Task::InvalidTransition)
      expect(task.update_columns(lease_expires_at: nil)).to be(true)
      expect { Task.create!(task_batch: task.task_batch, host:, task_type: "refresh_reports", state: "running", expires_at: 1.day.from_now, timeout_seconds: 60) }
        .to raise_error(Task::InvalidTransition, "new tasks start queued")
    end

    it "is never destroyed" do
      expect { task_in("queued").destroy }.to raise_error(ActiveRecord::ReadOnlyRecord, "tasks are never deleted")
    end

    it "limits stored output" do
      expect { task_in("running").succeed!(actor: host, output: "x" * (Task::MAX_OUTPUT_BYTES + 1)) }
        .to raise_error(ActiveRecord::RecordInvalid, /Output is longer than/)
    end
  end

  describe "the tasks_guard trigger, for code paths that skip the model" do
    it "refuses a transition outside the table" do
      task = task_in("queued")
      expect { in_savepoint { Task.where(id: task.id).update_all(state: "succeeded") } }.to raise_error(ActiveRecord::StatementInvalid, /invalid task state transition: queued -> succeeded/)
      expect { in_savepoint { Task.where(id: task_in("running").id).update_all(state: "queued") } }.to raise_error(ActiveRecord::StatementInvalid, /running -> queued/)
    end

    it "refuses any change to a terminal task" do
      task = task_in("expired")
      expect { in_savepoint { Task.where(id: task.id).update_all(output: "late") } }.to raise_error(ActiveRecord::StatementInvalid, /is expired, which is final/)
    end

    it "refuses a change to the type, parameters, host, batch, expiry, or timeout" do
      task = task_in("claimed")
      { task_type: "apply_package_updates", parameters: { "x" => 1 }, host_id: create(:host).id, expires_at: 1.year.from_now, timeout_seconds: 5 }.each do |column, value|
        expect { in_savepoint { Task.where(id: task.id).update_all(column => value) } }.to raise_error(ActiveRecord::StatementInvalid, /never change/), column.to_s
      end
    end

    it "refuses a task that does not start queued, and any delete" do
      task = task_in("queued")
      row = task.attributes.except("id", "uuid").merge("state" => "running")
      expect { in_savepoint { Task.insert_all!([ row ]) } }.to raise_error(ActiveRecord::StatementInvalid, /new tasks start queued/)
      expect { in_savepoint { Task.where(id: task.id).delete_all } }.to raise_error(ActiveRecord::StatementInvalid, /tasks are never deleted/)
      expect { in_savepoint { Task.connection.execute("TRUNCATE tasks CASCADE") } }.to raise_error(ActiveRecord::StatementInvalid)
    end

    it "checks the reason and state in the database too" do
      task = task_in("queued")
      expect { in_savepoint { Task.where(id: task.id).update_all(state: "refused") } }.to raise_error(ActiveRecord::StatementInvalid, /tasks_reason_for_failed_and_refused/)
    end
  end

  describe "helpers" do
    it "answers timeout, expiry, and claim-time refusal" do
      task = task_in("queued")
      expect(task.timeout).to eq(10.minutes)
      expect(task.expired_by?(task.expires_at - 1.second)).to be(false)
      expect(task.expired_by?(task.expires_at)).to be(true)
      expect(task.refusal_reason).to be_nil
      expect(task.uuid).to match(/\A\h{8}-\h{4}-4\h{3}-\h{4}-\h{12}\z/)
      stub_catalog_without("refresh_reports")
      expect(task.refusal_reason).to eq("unknown_type")
    end

    it "scopes open and terminal tasks" do
      open_task = task_in("running")
      done = task_in("refused")
      expect(Task.open_now).to include(open_task)
      expect(Task.open_now).not_to include(done)
      expect(Task.terminal).to contain_exactly(done)
    end
  end
end
