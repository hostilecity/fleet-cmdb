require "rails_helper"

# The task endpoints (P3-S03, P3-S04, FR-3.2, AC-3.3, AC-3.7, AC-3.8): poll and atomic claim, start, progress,
# and results. Every response is checked against its docs/api schema.
RSpec.describe "Task API", type: :request do
  let(:operator) { create(:operator) }
  let!(:agent) { task_agent }
  let(:host) { agent.first }
  let(:credential) { agent.last }

  # An enrolled, active host with a credential whose agent supports and enables every catalog type (P3-A01).
  def task_agent(**attributes)
    host, credential = enrolled_host(**attributes)
    host.update_columns(task_catalog_version: TaskCatalog.current.version, task_types_supported: TaskCatalog.current.types,
                        task_types_enabled: TaskCatalog.current.types, task_services_allowed: %w[nginx.service],
                        task_capabilities_reported_at: Time.current)
    [ host, credential ]
  end

  def versions(agent_version: "0.3.0") = { "schema_version" => 1, "agent_version" => agent_version }

  def poll(as: credential, **options) = post_api("/api/v1/tasks/poll", versions(**options), as)

  def start(task, as: credential, started_at: "2026-01-01T12:00:05Z") = post_api("/api/v1/tasks/#{uuid(task)}/start", versions.merge("started_at" => started_at), as)

  def progress(task, percent: 40, as: credential) = post_api("/api/v1/tasks/#{uuid(task)}/progress", versions.merge("percent" => percent), as)

  def report(task, payload = result_payload, as: credential) = post_api("/api/v1/tasks/#{uuid(task)}/result", payload, as)

  def uuid(task) = task.respond_to?(:uuid) ? task.uuid : task

  def result_payload(**fields)
    versions.merge("report_id" => "00000000-0000-4000-8000-000000000001", "outcome" => "succeeded", "reason" => nil, "exit_status" => 0,
                   "started_at" => "2026-01-01T12:00:05Z", "finished_at" => "2026-01-01T12:00:09Z", "details" => { "reports_sent" => %w[config inventory packages] },
                   "output" => "sent 3 reports\n", "output_truncated" => false).merge(fields.stringify_keys)
  end

  def conforms(name) = expect(ApiContract.errors(name, "v1", json)).to eq([])

  def queued_task(type: "refresh_reports", parameters: {}, for_host: host, now: Time.current)
    request = { "type" => type, "parameters" => parameters, "target" => { "host_ids" => [ for_host.id ] } }
    TaskBatches.create!(request, operator:, now:).tasks.sole
  end

  def restart_task(**options)
    allow_restart("nginx.service") unless TaskAllowedService.exists?(service: "nginx.service")
    queued_task(type: "restart_service", parameters: { "service" => "nginx.service" }, **options)
  end

  def running_task(type: "refresh_reports", **options)
    task = type == "restart_service" ? restart_task(**options) : queued_task(type:, **options)
    task.claim!(actor: host, lease_expires_at: 5.minutes.from_now)
    task.start!(actor: host, lease_expires_at: 15.minutes.from_now)
  end

  def entries(action, task) = AuditEntry.where(action:, target_type: "Task", target_id: task.id)

  describe "POST /api/v1/tasks/poll (P3-S03)" do
    it "answers with no task when there is nothing to do (task-poll.response)" do
      poll
      expect(response).to have_http_status(:ok)
      expect(json).to eq("task" => nil, "poll_seconds" => 30)
      conforms("task-poll.response")
    end

    it "claims the oldest queued task, with a lease, and delivers only its id, type, parameters, deadline, and catalog version" do
      older = restart_task(now: 2.minutes.ago)
      queued_task
      freeze_time do
        poll
        expect(response).to have_http_status(:ok)
        conforms("task-poll.response")
        expect(json).to eq("task" => { "id" => older.uuid, "type" => "restart_service", "parameters" => { "service" => "nginx.service" },
                                       "timeout_seconds" => 300, "catalog_version" => TaskCatalog.current.version }, "poll_seconds" => 30)
        expect(older.reload).to have_attributes(state: "claimed", claimed_at: Time.current, lease_expires_at: Time.current + AgentTasks::CLAIM_LEASE)
      end
      entry = entries(Audit::Actions::TASK_CLAIMED, older).sole
      expect(entry).to have_attributes(actor_type: "host", actor_id: host.id)
    end

    it "delivers an unstarted claimed task again, as after an agent restart, with a fresh lease and no second claim (AC-3.3)" do
      task = queued_task
      poll
      first_lease = task.reload.lease_expires_at
      travel(1.minute) do
        poll
        expect(json.dig("task", "id")).to eq(task.uuid)
        expect(task.reload.lease_expires_at).to be > first_lease
      end
      expect(entries(Audit::Actions::TASK_CLAIMED, task).count).to eq(1)
    end

    it "holds one task at a time: a second queued task waits while the first is claimed" do
      first = queued_task(now: 1.minute.ago)
      queued_task
      2.times { poll }
      expect(json.dig("task", "id")).to eq(first.uuid)
      expect(host.tasks.where(state: "claimed").count).to eq(1)
    end

    it "never delivers a started task again, nor anything else while it runs (AC-3.3)" do
      task = queued_task
      queued_task
      poll
      start(task)
      poll
      expect(json).to eq("task" => nil, "poll_seconds" => 30)
      expect(task.reload.state).to eq("running")
      expect(host.tasks.where(state: "claimed")).to be_empty
    end

    it "never delivers a queued task past its expiry, by the database clock (AC-3.8)" do
      expired = queued_task(now: 24.hours.ago - 1.second)
      poll
      expect(json).to eq("task" => nil, "poll_seconds" => 30)
      expect(expired.reload.state).to eq("queued") # the expiry job (P3-S05) marks it expired; the poll only skips it
    end

    it "skips an expired task for the next one that is still valid (AC-3.8)" do
      queued_task(now: 25.hours.ago)
      fresh = queued_task
      poll
      expect(json.dig("task", "id")).to eq(fresh.uuid)
    end

    it "expires a claimed task past its expiry instead of delivering it again, and moves on to the next (P3-S05)" do
      task = queued_task(now: 24.hours.ago + 2.seconds)
      poll
      expect(json.dig("task", "id")).to eq(task.uuid)
      fresh = queued_task
      sleep 2.1 # the database clock passes the expiry
      poll
      expect(json.dig("task", "id")).to eq(fresh.uuid) # the expired claim no longer blocks the host
      expect(task.reload.state).to eq("expired")
      expect(entries(Audit::Actions::TASK_REQUEUED, task).sole).to have_attributes(actor_type: "system")
      expect(entries(Audit::Actions::TASK_EXPIRED, task).sole).to have_attributes(actor_type: "system")
      start(task)
      expect(json).to eq("id" => task.uuid, "state" => "expired", "run" => false)
    end

    it "refuses at claim time a task that no longer passes the server's policy, and delivers the next one (P3-S06, threat model C14)" do
      restart = restart_task(now: 1.minute.ago)
      refresh = queued_task
      TaskAllowedService.delete_all # removed from the allowlist while queued
      poll
      expect(json.dig("task", "id")).to eq(refresh.uuid)
      expect(restart.reload).to have_attributes(state: "refused", reason: "not_allowed_on_server")
      expect(entries(Audit::Actions::TASK_REFUSED, restart).sole).to have_attributes(actor_type: "system")
      expect(entries(Audit::Actions::TASK_CLAIMED, restart)).to be_empty
    end

    it "refuses a claimed task that no longer passes when it would be delivered again" do
      task = restart_task
      poll
      TaskAllowedService.delete_all
      poll
      expect(json).to eq("task" => nil, "poll_seconds" => 30)
      expect(task.reload).to have_attributes(state: "refused", reason: "not_allowed_on_server")
    end

    it "refuses a task whose type has left the catalog" do
      task = queued_task
      stub_catalog_without("refresh_reports")
      poll
      expect(json).to eq("task" => nil, "poll_seconds" => 30)
      expect(task.reload).to have_attributes(state: "refused", reason: "unknown_type")
    end

    it "gives up after a bounded number of refusals in one poll" do
      stub_const("AgentTasks::MAX_REFUSALS_PER_POLL", 1)
      2.times { queued_task }
      stub_catalog_without("refresh_reports")
      poll
      expect(json).to eq("task" => nil, "poll_seconds" => 30)
      expect(host.tasks.pluck(:state).tally).to eq("refused" => 1, "queued" => 1)
    end

    it "never delivers another host's task" do
      other, = task_agent(hostname: "vm-02.example.lan")
      task = queued_task(for_host: other)
      poll
      expect(json).to eq("task" => nil, "poll_seconds" => 30)
      expect(task.reload.state).to eq("queued")
    end

    it "needs the host's credential, an active host, and a supported agent version" do
      poll(as: nil)
      expect_error(:unauthorized, "unauthorized")
      poll(agent_version: "0.0.1")
      expect_error(:upgrade_required, "agent_version_unsupported")
      Enrollment::IssueToken.call(host:, actor: Audit::SYSTEM)
      poll
      expect_error(:forbidden, "reenrollment_required")
    end

    it "refuses a body that fails the schema" do
      post_api("/api/v1/tasks/poll", { "schema_version" => 1 }, credential)
      expect_error(:bad_request, "validation_failed")
    end
  end

  describe "POST /api/v1/tasks/:id/start (P3-S03)" do
    let!(:task) { queued_task }

    before { poll }

    it "moves the claimed task to running and tells the agent to run it (task-start.response)" do
      freeze_time do
        start(task)
        expect(response).to have_http_status(:ok)
        conforms("task-start.response")
        expect(json).to eq("id" => task.uuid, "state" => "running", "run" => true)
        expect(task.reload).to have_attributes(state: "running", started_at: Time.current, agent_started_at: Time.utc(2026, 1, 1, 12, 0, 5),
                                               lease_expires_at: Time.current + task.timeout + AgentTasks::RESULT_GRACE)
      end
      expect(entries(Audit::Actions::TASK_STARTED, task).sole).to have_attributes(actor_type: "host", actor_id: host.id)
    end

    it "is idempotent: a repeated start still says run, and is audited once" do
      2.times { start(task) }
      expect(json).to include("state" => "running", "run" => true)
      expect(entries(Audit::Actions::TASK_STARTED, task).count).to eq(1)
    end

    it "tells the agent not to run a task that was cancelled before it started" do
      task.reload.cancel!(actor: operator)
      start(task)
      expect(json).to eq("id" => task.uuid, "state" => "cancelled", "run" => false)
      conforms("task-start.response")
    end

    it "tells the agent not to run a task that is back in the queue, and lets it start once the next poll claims it again (threat model L2, P3-S05)" do
      task.reload.requeue!(actor: Audit::SYSTEM)
      start(task)
      expect(json).to include("state" => "queued", "run" => false)
      poll
      expect(json.dig("task", "id")).to eq(task.uuid) # the same id: the agent finds it in its ledger, never executed
      start(task)
      expect(json).to include("state" => "running", "run" => true)
    end

    it "refuses, and tells the agent not to run, a task that stopped passing the server's policy after it was claimed" do
      stub_catalog_without("refresh_reports")
      start(task)
      expect(json).to include("state" => "refused", "run" => false)
      expect(task.reload.reason).to eq("unknown_type")
    end

    it "answers 404 for another host's task, an unknown id, or a malformed one, alike" do
      other, other_credential = task_agent(hostname: "vm-02.example.lan")
      start(task, as: other_credential)
      expect_error(:not_found, "not_found")
      not_found = json.dig("error", "message")
      start("00000000-0000-4000-8000-00000000ffff")
      expect_error(:not_found, "not_found")
      expect(json.dig("error", "message")).to eq(not_found)
      start("42")
      expect_error(:not_found, "not_found")
      expect(task.reload.state).to eq("claimed")
      expect(other.tasks).to be_empty
    end

    it "refuses a start without the agent's start time" do
      post_api("/api/v1/tasks/#{task.uuid}/start", versions, credential)
      expect_error(:bad_request, "validation_failed")
      expect(task.reload.state).to eq("claimed")
    end
  end

  describe "POST /api/v1/tasks/:id/progress (P3-S04)" do
    it "records a running task's progress (task-progress.response)" do
      task = running_task
      freeze_time do
        progress(task, percent: 40)
        expect(response).to have_http_status(:ok)
        conforms("task-progress.response")
        expect(json).to eq("id" => task.uuid, "state" => "running")
        expect(task.reload).to have_attributes(progress_percent: 40, progress_reported_at: Time.current)
      end
      progress(task, percent: nil)
      expect(task.reload.progress_percent).to be_nil
    end

    it "ignores progress for a task that is not running, and says what state it is in" do
      task = running_task
      task.time_out!(actor: Audit::SYSTEM)
      progress(task)
      expect(json).to eq("id" => task.uuid, "state" => "timed_out")
      expect(task.reload.progress_percent).to be_nil
    end

    it "answers 404 for another host's task" do
      _, other_credential = task_agent(hostname: "vm-02.example.lan")
      task = running_task
      progress(task, as: other_credential)
      expect_error(:not_found, "not_found")
      expect(task.reload.progress_percent).to be_nil
    end
  end

  describe "POST /api/v1/tasks/:id/result (P3-S04)" do
    it "applies a result to a running task, with the agent's times kept apart (task-result.response)" do
      task = running_task
      freeze_time do
        report(task)
        expect(response).to have_http_status(:ok)
        conforms("task-result.response")
        expect(json).to eq("id" => task.uuid, "report_id" => "00000000-0000-4000-8000-000000000001", "duplicate" => false, "applied" => true, "state" => "succeeded")
        expect(task.reload).to have_attributes(
          state: "succeeded", exit_status: 0, output: "sent 3 reports\n", output_truncated: false, finished_at: Time.current, lease_expires_at: nil,
          agent_started_at: Time.utc(2026, 1, 1, 12, 0, 5), agent_finished_at: Time.utc(2026, 1, 1, 12, 0, 9),
          result_report_id: "00000000-0000-4000-8000-000000000001", result_received_at: Time.current,
          result_details: { "reports_sent" => %w[config inventory packages] }
        )
      end
      entry = entries(Audit::Actions::TASK_SUCCEEDED, task).sole
      expect(entry).to have_attributes(actor_type: "host", actor_id: host.id)
      expect(entry.changeset.to_json).not_to include("sent 3 reports") # output never reaches the audit log
    end

    it "keeps only the details it knows" do
      task = running_task(type: "apply_package_updates")
      report(task, result_payload(details: { "reboot_required" => true, "services_needing_restart" => %w[cron.service], "unit_active" => nil, "shell" => "sh" }))
      expect(task.reload.result_details).to eq("reboot_required" => true, "services_needing_restart" => %w[cron.service])
      report(running_task, result_payload(report_id: "00000000-0000-4000-8000-000000000002", details: nil))
      expect(host.tasks.order(:id).last.result_details).to be_nil
    end

    it "accepts the same result again and changes nothing (duplicate: true)" do
      task = running_task
      report(task)
      expect { report(task) }.not_to change { [ AuditEntry.count, task.reload.updated_at ] }
      expect(json).to include("duplicate" => true, "applied" => true, "state" => "succeeded")
      report(task, result_payload(report_id: "00000000-0000-4000-8000-000000000009")) # a new report id, the same result
      expect(json).to include("duplicate" => true)
    end

    it "refuses a conflicting second result with 409, audited and logged, and leaves the first in place" do
      task = running_task
      report(task)
      allow(Rails.logger).to receive(:warn).and_call_original
      report(task, result_payload(outcome: "failed", reason: "nonzero_exit", exit_status: 1))
      expect_error(:conflict, "task_conflict")
      expect(task.reload).to have_attributes(state: "succeeded", exit_status: 0)
      entry = entries(Audit::Actions::TASK_RESULT_CONFLICT, task).sole
      expect(entry).to have_attributes(actor_type: "host", changeset: include("conflict" => "different_result", "outcome" => "failed", "state" => "succeeded"))
      expect(Rails.logger).to have_received(:warn).with(/task #{task.uuid} result refused \(different_result\)/)
    end

    it "records an agent-side refusal of a claimed task with its reason, which is how AC-3.1 is observed" do
      task = queued_task
      poll
      report(task, result_payload(outcome: "refused", reason: "not_enabled_locally", exit_status: nil, started_at: nil, output: nil, details: nil))
      expect(json).to include("applied" => true, "state" => "refused")
      expect(task.reload).to have_attributes(state: "refused", reason: "not_enabled_locally", agent_started_at: nil, output: nil)
      expect(entries(Audit::Actions::TASK_REFUSED, task).sole).to have_attributes(actor_type: "host", changeset: include("reason" => "not_enabled_locally"))
    end

    it "records an interrupted task the agent found started but unacknowledged after a restart (P3-A02)" do
      task = queued_task
      poll
      report(task, result_payload(outcome: "failed", reason: "interrupted", exit_status: nil, output: nil))
      expect(task.reload).to have_attributes(state: "failed", reason: "interrupted")
    end

    it "applies a timeout, and a cancellation of an interruptible task" do
      timed_out = running_task(type: "apply_package_updates")
      report(timed_out, result_payload(outcome: "timed_out", exit_status: nil, output_truncated: true))
      expect(timed_out.reload).to have_attributes(state: "timed_out", output_truncated: true)
      cancelled = running_task
      report(cancelled, result_payload(outcome: "cancelled", report_id: "00000000-0000-4000-8000-000000000002"))
      expect(cancelled.reload.state).to eq("cancelled")
    end

    it "refuses a result the task's state cannot take with 409, audited: success for a task never started, a result for a queued one, or cancelling a non-interruptible one" do
      claimed = queued_task
      poll
      report(claimed)
      expect_error(:conflict, "task_conflict")
      expect(claimed.reload.state).to eq("claimed")
      expect(entries(Audit::Actions::TASK_RESULT_CONFLICT, claimed).sole.changeset).to include("conflict" => "state", "state" => "claimed")

      claimed.requeue!(actor: Audit::SYSTEM)
      report(claimed, result_payload(outcome: "failed", reason: "interrupted"))
      expect_error(:conflict, "task_conflict")

      restart = running_task(type: "restart_service")
      report(restart, result_payload(outcome: "cancelled"))
      expect_error(:conflict, "task_conflict")
      expect(restart.reload.state).to eq("running")
    end

    it "never lets an agent cancel a claimed task, or cancel or refuse a queued one: those are the operator's and the server's" do
      claimed = restart_task
      poll
      report(claimed, result_payload(outcome: "cancelled"))
      expect_error(:conflict, "task_conflict")
      expect(claimed.reload.state).to eq("claimed")

      queued = queued_task # waits: the host holds a claimed task
      report(queued, result_payload(outcome: "refused", reason: "not_enabled_locally"))
      expect_error(:conflict, "task_conflict")
      report(queued, result_payload(outcome: "cancelled"))
      expect_error(:conflict, "task_conflict")
      expect(queued.reload.state).to eq("queued")
      expect(entries(Audit::Actions::TASK_RESULT_CONFLICT, queued).count).to eq(2)
    end

    it "stores the largest details the schema allows, applied or late" do
      services = Array.new(64) { |i| "#{format('%03d', i)}#{'s' * 244}.service" }
      details = { "reboot_required" => true, "services_needing_restart" => services, "unit_active" => true, "reports_sent" => %w[config inventory packages] }
      expect(ApiContract.errors("task-result.request", "v1", result_payload(details:))).to eq([])
      applied = running_task(type: "apply_package_updates")
      report(applied, result_payload(details:))
      expect(response).to have_http_status(:ok)
      expect(applied.reload.result_details["services_needing_restart"].size).to eq(64)
      late = running_task(type: "apply_package_updates")
      late.time_out!(actor: Audit::SYSTEM)
      report(late, result_payload(details:, report_id: "00000000-0000-4000-8000-000000000002"))
      expect(response).to have_http_status(:ok)
      expect(late.reload.late_result.details["services_needing_restart"].size).to eq(64)
    end

    it "keeps a late result for a task the server already ended as an annotation, without changing its state (threat model L4)" do
      task = running_task(type: "apply_package_updates")
      task.time_out!(actor: Audit::SYSTEM)
      freeze_time do
        report(task, result_payload(outcome: "succeeded", details: { "reboot_required" => true }, output: "done\e[0m\n"))
        expect(json).to eq("id" => task.uuid, "report_id" => "00000000-0000-4000-8000-000000000001", "duplicate" => false, "applied" => false, "state" => "timed_out")
        conforms("task-result.response")
        expect(task.reload.late_result).to have_attributes(outcome: "succeeded", exit_status: 0, details: { "reboot_required" => true }, output: "done\n",
                                                           agent_finished_at: Time.utc(2026, 1, 1, 12, 0, 9), received_at: Time.current)
      end
      expect(task.reload).to have_attributes(state: "timed_out", output: nil, result_digest: nil)
      expect(entries(Audit::Actions::TASK_LATE_RESULT, task).sole).to have_attributes(actor_type: "host", changeset: include("outcome" => "succeeded", "state" => "timed_out"))

      report(task, result_payload(outcome: "succeeded", details: { "reboot_required" => true }, output: "done\e[0m\n"))
      expect(json).to include("duplicate" => true, "applied" => false)
      report(task, result_payload(outcome: "failed", reason: "nonzero_exit"))
      expect_error(:conflict, "task_conflict")
      expect(TaskLateResult.count).to eq(1)
    end

    it "keeps a late result for an expired task too" do
      task = queued_task
      task.expire!(actor: Audit::SYSTEM)
      report(task, result_payload(outcome: "refused", reason: "not_supported", exit_status: nil, started_at: nil))
      expect(json).to include("applied" => false, "state" => "expired")
      expect(task.reload.late_result).to have_attributes(outcome: "refused", reason: "not_supported", agent_started_at: nil)
    end

    it "truncates oversize output with a clear marker, and keeps the agent's own truncation flag" do
      task = running_task
      output = "#{'a' * 40_000}#{'é' * 20_000}#{'z' * 40_000}"
      report(task, result_payload(output:))
      stored = task.reload.output
      expect(task.output_truncated).to be(true)
      expect(stored.bytesize).to be <= TaskOutput::LIMIT_BYTES
      expect(stored).to start_with("a" * 1_000).and end_with("z" * 1_000)
      expect(stored).to match(/\n\[\.\.\. \d+ bytes of output cut here by the server \.\.\.\]\n/)
      expect(stored).to be_valid_encoding

      flagged = running_task
      report(flagged, result_payload(report_id: "00000000-0000-4000-8000-000000000002", output: "short", output_truncated: true))
      expect(flagged.reload).to have_attributes(output: "short", output_truncated: true)
    end

    it "stores output with markup and control characters as inert text" do
      task = running_task
      report(task, result_payload(output: "<script>alert(1)</script>\r\n\e[31mred\e[0m\u0000\u0007\u202Eevil\ttab\n"))
      expect(task.reload.output).to eq("<script>alert(1)</script>\nredevil\ttab\n") # markup stays text; the dashboard escapes it (P3-S10)
    end

    it "replaces invalid UTF-8 in the output, and refuses a body with a lone surrogate escape" do
      task = running_task
      body = %({"schema_version":1,"agent_version":"0.3.0","report_id":"00000000-0000-4000-8000-000000000001","outcome":"succeeded","finished_at":"2026-01-01T12:00:09Z","output":"a\xFFb"})
      report(task, body.b)
      expect(response).to have_http_status(:ok)
      expect(task.reload.output).to eq("a\uFFFDb")
      report(running_task, body.b.sub("a\xFFb".b, "a\\ud800b".b))
      expect_error(:bad_request, "validation_failed")
    end

    it "refuses a reason the agent may not give, such as lease_expired" do
      task = running_task
      report(task, result_payload(outcome: "failed", reason: "lease_expired"))
      expect_error(:bad_request, "validation_failed")
      expect(task.reload.state).to eq("running")
    end

    it "answers 404 for another host's task, and changes nothing" do
      _, other_credential = task_agent(hostname: "vm-02.example.lan")
      task = running_task
      report(task, as: other_credential)
      expect_error(:not_found, "not_found")
      expect(task.reload.state).to eq("running")
      expect(AuditEntry.where(action: Audit::Actions::TASK_RESULT_CONFLICT)).to be_empty
    end

    it "takes a body up to 1 MiB and refuses a larger one" do
      task = running_task
      report(task, result_payload(output: "x" * 131_072))
      expect(response).to have_http_status(:ok)
      report(running_task, result_payload(output: "x" * 1.megabyte))
      expect_error(:content_too_large, "payload_too_large")
    end
  end

  describe "task controls (P3-S05, P3-S06)" do
    it "expires a claimed task whose start arrives after its expiry, before the job ran, instead of starting it (review of #167)" do
      task = queued_task(now: 24.hours.ago + 2.seconds)
      poll
      sleep 2.1 # the database clock passes the expiry
      start(task)
      expect(json).to eq("id" => task.uuid, "state" => "expired", "run" => false)
      expect(entries(Audit::Actions::TASK_EXPIRED, task).sole).to have_attributes(actor_type: "system")
      expect(entries(Audit::Actions::TASK_STARTED, task)).to be_empty
    end

    it "sends the poll interval hint from the settings" do
      TaskSettings.update_limits!({ "poll_seconds" => "120" }, actor: operator)
      poll
      expect(json).to eq("task" => nil, "poll_seconds" => 120)
      conforms("task-poll.response")
    end

    it "names a running interruptible task the operator asked to cancel, in the poll and progress responses, until its result" do
      task = running_task
      poll
      expect(json).not_to have_key("cancel")
      progress(task)
      expect(json).to eq("id" => task.uuid, "state" => "running")
      TaskCancellation.cancel_task!(task, operator:)
      poll
      expect(json).to eq("task" => nil, "poll_seconds" => 30, "cancel" => { "id" => task.uuid })
      conforms("task-poll.response")
      progress(task)
      expect(json).to eq("id" => task.uuid, "state" => "running", "cancel" => { "id" => task.uuid })
      conforms("task-progress.response")
      report(task, result_payload(outcome: "cancelled", exit_status: nil, details: nil))
      expect(task.reload.state).to eq("cancelled")
      expect(entries(Audit::Actions::TASK_CANCELLED, task).sole).to have_attributes(actor_type: "host")
      poll
      expect(json).not_to have_key("cancel")
      progress(task)
      expect(json).to eq("id" => task.uuid, "state" => "cancelled")
    end

    it "never names a non-interruptible task: it runs to completion (Q17)" do
      task = running_task(type: "restart_service")
      TaskCancellation.cancel_task!(task, operator:)
      poll
      expect(json).not_to have_key("cancel")
      progress(task)
      expect(json).not_to have_key("cancel")
      report(task)
      expect(task.reload).to have_attributes(state: "succeeded", cancel_requested?: true)
    end

    it "never delivers a cancelled queued task (AC-3.6)" do
      task = queued_task
      TaskCancellation.cancel_task!(task, operator:)
      poll
      expect(json["task"]).to be_nil
      start(task)
      expect(json).to eq("id" => task.uuid, "state" => "cancelled", "run" => false)
    end

    it "keeps output to the configured limit" do
      TaskSettings.update_limits!({ "output_limit_kib" => "4" }, actor: operator)
      task = running_task
      report(task, result_payload(output: "x" * 10_000))
      expect(task.reload).to have_attributes(output_truncated: true)
      expect(task.output.bytesize).to be <= 4.kilobytes
    end

    it "refuses at claim time a restart whose only allowlist entry is for a tag the host no longer has (Q31)" do
      TaskAllowedService.delete_all
      allow_restart("nginx.service", tag: "web")
      host.update!(tags: %w[web])
      task = restart_task
      host.update!(tags: %w[db])
      poll
      expect(json["task"]).to be_nil
      expect(task.reload).to have_attributes(state: "refused", reason: "not_allowed_on_server")
    end

    describe "closing a task the agent holds but never ran (failed, not_run; threat model L2)" do
      def not_run(task, report_id: "00000000-0000-4000-8000-0000000000b1")
        report(task, result_payload(report_id:, outcome: "failed", reason: "not_run", exit_status: nil, details: nil, output: nil))
      end

      it "accepts it for a task delivered again after its start was refused, audited with the host as actor" do
        task = queued_task
        poll
        task.reload.requeue!(actor: Audit::SYSTEM) # the claim lapsed before the start arrived
        start(task)
        expect(json).to include("state" => "queued", "run" => false)
        poll
        expect(json.dig("task", "id")).to eq(task.uuid) # delivered again: the agent has it in its ledger
        not_run(task)
        expect(response).to have_http_status(:ok)
        expect(json).to include("applied" => true, "state" => "failed")
        conforms("task-result.response")
        expect(task.reload).to have_attributes(state: "failed", reason: "not_run", started_at: nil)
        expect(entries(Audit::Actions::TASK_FAILED, task).sole).to have_attributes(actor_type: "host", actor_id: host.id, changeset: { "state" => %w[claimed failed], "reason" => "not_run" })
        not_run(task)
        expect(json).to include("duplicate" => true)
        poll
        expect(json["task"]).to be_nil # the host is free again
      end

      it "accepts it for a task back in the queue that this host had claimed, before the next poll" do
        task = queued_task
        poll
        task.reload.requeue!(actor: Audit::SYSTEM)
        not_run(task)
        expect(task.reload).to have_attributes(state: "failed", reason: "not_run")
        expect(entries(Audit::Actions::TASK_FAILED, task).sole.changeset).to eq("state" => %w[queued failed], "reason" => "not_run")
      end

      it "refuses it for a queued task this host never claimed, and for a running task, which was told to run" do
        never = queued_task
        not_run(never)
        expect(response).to have_http_status(:conflict)
        expect(never.reload.state).to eq("queued")
        running = running_task
        not_run(running, report_id: "00000000-0000-4000-8000-0000000000b2")
        expect(response).to have_http_status(:conflict)
        expect(running.reload.state).to eq("running")
      end
    end
  end
end
