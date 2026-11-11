require "rails_helper"

# Cancelling from the dashboard (P3-S05, P3-DASH-TASKS, FR-3.4; mockup cancel.html): any operator, with a recent second
# factor (Q23), on the server. Each cancel has a confirmation page that says what it can and cannot do.
RSpec.describe "Task cancellation", type: :request do
  include_context "signed in operator"

  let(:secret) { @secret }
  let(:creator) { create(:operator) }

  before { @secret = enrol_second_factor(operator).first }

  def code = { second_factor_code: totp_code(secret) }

  def run(task)
    task.claim!(actor: task.host, lease_expires_at: 5.minutes.from_now)
    task.start!(actor: task.host, lease_expires_at: 1.hour.from_now)
  end

  it "refuses a cancel without a code: nothing changes, 403, and the confirmation is drawn again with why" do
    task = create_task(task_host, operator: creator)
    post "/tasks/#{task.id}/cancel"
    expect(response).to have_http_status(:forbidden)
    expect(page.at_css("#dialog_title").text).to eq("Cancel task ##{task.id} on #{task.host.name}?")
    expect(page.at_css("#cancel_form input[name=second_factor_code]")).to be_present
    expect(task.reload.state).to eq("queued")
    post "/tasks/batches/#{task.task_batch_id}/cancel", params: { second_factor_code: "000000" }
    expect(response).to have_http_status(:forbidden)
    expect(page.at_css("#cancel_form .error-text").text).to start_with("That code was not accepted, and nothing was done.")
    expect(page.at_css("#dialog_title").text).to eq("Cancel the rest of batch #{task.task_batch_id}?")
    expect(task.reload.state).to eq("queued")
    expect(AuditEntry.where(action: Audit::Actions::SECOND_FACTOR_STEP_UP_FAILED).sole.changeset["purpose"]).to eq("cancel_task")
  end

  it "cancels another operator's queued task with a code and goes to the task's page" do
    host = task_host(name: "sim-028")
    task = create_task(host, operator: creator)
    post "/tasks/#{task.id}/cancel", params: code, headers: { "Referer" => "http://#{HostSeparation.dashboard_host}/audit" }
    expect(response).to redirect_to("/tasks/#{task.id}")
    expect(flash[:notice]).to eq("Task ##{task.id} cancelled. sim-028 will never run it.")
    expect(task.reload.state).to eq("cancelled")
    follow_redirect!
    expect(page.at_css("#result h2").text).to eq("Cancelled before it was delivered")
    expect(AuditEntry.where(action: Audit::Actions::TASK_CANCELLED).sole).to have_attributes(actor_type: "operator", actor_id: operator.id)
  end

  it "says what a cancel of a running task did, and refuses a finished one" do
    stoppable = run(create_task(task_host, operator: creator))
    post "/tasks/#{stoppable.id}/cancel", params: code
    expect(response).to redirect_to("/tasks/#{stoppable.id}")
    expect(flash[:notice]).to start_with("Stop requested. Task ##{stoppable.id}")
    post "/tasks/#{stoppable.id}/cancel"
    expect(flash[:notice]).to eq("Cancel was already requested for task ##{stoppable.id}. Nothing else was changed.")

    hosts = Array.new(2) { task_host }
    batch = create_task_batch(hosts, type: "apply_package_updates", operator: creator)
    unstoppable = run(batch.tasks.first)
    post "/tasks/#{unstoppable.id}/cancel"
    expect(flash[:notice]).to eq("Cancel requested. Task ##{unstoppable.id} keeps running until it finishes; 1 task in batch #{batch.batch.id} that had not started was cancelled.")

    lone = run(create_task(task_host, type: "apply_package_updates", operator: creator))
    post "/tasks/#{lone.id}/cancel"
    expect(flash[:notice]).to eq("Cancel requested. Task ##{lone.id} keeps running until it finishes.")

    finished = create_task(task_host, operator: creator)
    finished.expire!(actor: Audit::SYSTEM, now: Time.utc(2026, 11, 8, 14, 7))
    post "/tasks/#{finished.id}/cancel"
    expect(flash[:alert]).to eq("Not cancelled: task ##{finished.id} already finished. It ended expired at 2026-11-08 14:07 UTC, before your request. A finished task cannot be cancelled.")
  end

  it "cancels the rest of a batch and counts what changed" do
    hosts = Array.new(4) { task_host }
    result = create_task_batch(hosts, type: "apply_package_updates", operator: creator)
    running, *, finished = result.tasks
    run(running)
    run(finished).succeed!(actor: finished.host, exit_status: 0)
    post "/tasks/batches/#{result.batch.id}/cancel", params: code
    expect(response).to redirect_to("/tasks/batches/#{result.batch.id}")
    expect(flash[:notice]).to eq("Batch #{result.batch.id}: 2 waiting tasks cancelled and 1 running task cannot be stopped safely and runs to completion. 1 finished task not changed. Nothing is undone.")
    refresh = create_task_batch(Array.new(2) { task_host }, operator: creator)
    run(refresh.tasks.first)
    post "/tasks/batches/#{refresh.batch.id}/cancel"
    expect(flash[:notice]).to eq("Batch #{refresh.batch.id}: 1 waiting task cancelled and 1 running task asked to stop. 0 finished tasks not changed. Nothing is undone.")
  end

  it "answers 404 for a task or batch that does not exist" do
    post "/tasks/999999/cancel", params: code
    expect(response).to have_http_status(:not_found)
    post "/tasks/batches/999999/cancel"
    expect(response).to have_http_status(:not_found)
    get "/tasks/999999/cancel"
    expect(response).to have_http_status(:not_found)
    get "/tasks/batches/999999/cancel"
    expect(response).to have_http_status(:not_found)
  end

  describe "the confirmation (mockup cancel.html)" do
    def dialog = page.at_css(".dialog")

    it "says what a cancel does in each state, with the button named by what it can do, and writes nothing" do
      queued = create_task(task_host(name: "sim-028"), operator: creator)
      get "/tasks/#{queued.id}/cancel"
      expect(response).to have_http_status(:ok)
      expect(dialog.at_css("h2").text).to eq("Cancel task ##{queued.id} on sim-028?")
      expect(dialog.text).to include("sim-028 will never receive it")
      expect(dialog.at_css("button[type=submit]").text).to eq("Cancel task")
      expect(dialog.at_css("form")["action"]).to eq("/tasks/#{queued.id}/cancel")
      expect(dialog.css("input[name=second_factor_code]").size).to eq(1)
      expect(queued.reload.state).to eq("queued")

      claimed = create_task(task_host(name: "sim-031"), operator: creator)
      claimed.claim!(actor: claimed.host, lease_expires_at: 5.minutes.from_now)
      get "/tasks/#{claimed.id}/cancel"
      expect(dialog.text).to include("sim-031 has picked it up but has not started it.")

      stoppable = run(create_task(task_host, operator: creator))
      get "/tasks/#{stoppable.id}/cancel"
      expect(dialog.at_css("h2").text).to start_with("Stop task ##{stoppable.id}")
      expect(dialog.at_css("button[type=submit]").text).to eq("Stop task")
      expect(dialog.at_css("a.btn").text).to eq("Let it run")

      hosts = [ task_host(name: "sim-027"), task_host(name: "sim-028") ]
      batch = create_task_batch(hosts, type: "apply_package_updates", operator: creator)
      unstoppable = run(batch.tasks.first)
      get "/tasks/#{unstoppable.id}/cancel"
      expect(dialog.at_css("h2").text).to eq("Task ##{unstoppable.id} on sim-027 cannot be stopped")
      expect(dialog.text).to include("It will keep running until it finishes", "stop the 1 task in batch #{batch.batch.id} that has not started (sim-028)")
      expect(dialog.at_css("button[type=submit]").text).to eq("Cancel what has not started")
      expect(dialog.at_css("a.btn").text).to eq("Close")

      lone = run(create_task(task_host, type: "apply_package_updates", operator: creator))
      get "/tasks/#{lone.id}/cancel"
      expect(dialog.text).to include("It is not part of a batch, so there is nothing else to stop.")
      expect(dialog.at_css("button[type=submit]").text).to eq("Record a cancel request anyway")
      lone.request_cancel!(operator:)
      get "/tasks/#{lone.id}/cancel"
      expect(dialog.at_css("h2").text).to eq("Cancel was already requested for task ##{lone.id}")
      expect(dialog.css("form")).to be_empty

      batch.tasks.last.cancel!(actor: operator)
      get "/tasks/#{unstoppable.id}/cancel"
      expect(dialog.text).to include("No other task of batch #{batch.batch.id} is waiting to start")

      queued.cancel!(actor: operator)
      get "/tasks/#{queued.id}/cancel"
      expect(dialog.at_css("h2").text).to eq("Task ##{queued.id} on sim-028 has finished")
      expect(dialog.css("form")).to be_empty
    end

    it "does nothing when the task started after its confirmation was drawn, so the cancel never reaches the rest of the batch" do
      hosts = [ task_host(name: "sim-027"), task_host(name: "sim-028") ]
      batch = create_task_batch(hosts, type: "apply_package_updates", operator: creator)
      task, sibling = batch.tasks
      get "/tasks/#{task.id}/cancel"
      seen = page.at_css("#cancel_form input[name=seen]")["value"]
      expect(seen).to eq("unstarted")
      run(task) # the agent starts it before the operator submits
      post "/tasks/#{task.id}/cancel", params: code.merge(seen:)
      expect(response).to have_http_status(:conflict)
      expect(page.at_css(".notice.flash").text).to start_with("Nothing was done: task ##{task.id} is running now")
      expect(page.at_css("#dialog_title").text).to eq("Task ##{task.id} on sim-027 cannot be stopped")
      expect([ task.reload.cancel_requested?, sibling.reload.state ]).to eq([ false, "queued" ])
      post "/tasks/#{task.id}/cancel", params: { seen: page.at_css("#cancel_form input[name=seen]")["value"] }
      expect(response).to redirect_to("/tasks/#{task.id}")
      expect([ task.reload.cancel_requested?, sibling.reload.state ]).to eq([ true, "cancelled" ])
    end

    it "counts what a batch cancel will and will not change" do
      hosts = %w[sim-024 sim-025 sim-026 sim-027 sim-028].map { |name| task_host(name:) }
      result = create_task_batch(hosts, type: "apply_package_updates", operator: creator)
      done, running, already, *waiting = result.tasks
      run(done).succeed!(actor: done.host, exit_status: 0)
      run(running)
      run(already).request_cancel!(operator:)
      get "/tasks/batches/#{result.batch.id}/cancel"
      expect(page.css("#cancel_effects li").map { |li| li.text.squish }).to eq([
        "2 waiting tasks (sim-027, sim-028) become cancelled now and are never delivered.",
        "1 running task (sim-025) cannot be stopped safely and runs to completion, by #{(running.started_at + running.timeout).utc.strftime('%Y-%m-%d %H:%M:%S UTC')} at the latest.",
        "1 running task (sim-026) already has a cancel request.",
        "1 finished task is not changed. Nothing is undone."
      ])
      expect(page.at_css("#cancel_form button").text).to eq("Cancel the rest")
      expect(waiting.map { |task| task.reload.state }).to eq(%w[queued queued])

      refresh = create_task_batch(Array.new(2) { task_host }, operator: creator)
      run(refresh.tasks.first)
      get "/tasks/batches/#{refresh.batch.id}/cancel"
      expect(page.at_css("#cancel_effects").text.squish).to include("1 waiting task (#{refresh.tasks.last.host.name}) becomes cancelled", "1 running task (#{refresh.tasks.first.host.name}) can be stopped safely")

      TaskCancellation.cancel_batch!(result.batch, operator:)
      get "/tasks/batches/#{result.batch.id}/cancel"
      expect(page.at_css("#dialog_title").text).to eq("Nothing left to cancel in batch #{result.batch.id}")
      expect(page.at_css(".dialog").text).to include("Cancel was already requested for the 2 running tasks")
      running.succeed!(actor: running.host, exit_status: 0)
      already.succeed!(actor: already.host, exit_status: 0)
      get "/tasks/batches/#{result.batch.id}/cancel"
      expect(page.at_css(".dialog").text).to include("Every task has finished.")
    end

    it "is reached from the task and batch pages, and shows a passed second factor instead of the code box" do
      task = create_task(task_host, operator: creator)
      get "/tasks/#{task.id}"
      expect(page.at_css("#cancel_link")["href"]).to eq("/tasks/#{task.id}/cancel")
      get "/tasks/batches/#{task.task_batch_id}"
      expect(page.at_css("#cancel_link")["href"]).to eq("/tasks/batches/#{task.task_batch_id}/cancel")
      SecondFactors.step_up(operator_session: OperatorSession.order(:id).last, code: totp_code(secret), purpose: "cancel_task")
      get "/tasks/#{task.id}/cancel"
      expect(page.at_css("#cancel_form .stepup.passed")).to be_present
      expect(page.css("#cancel_form input[name=second_factor_code]")).to be_empty
    end
  end
end
