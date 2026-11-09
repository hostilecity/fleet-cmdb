require "rails_helper"

# Cancelling from the dashboard (P3-S05, FR-3.4): any operator, with a recent second factor (Q23), on the server.
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

  it "refuses a cancel without a code: nothing changes, 403" do
    task = create_task(task_host, operator: creator)
    post "/tasks/#{task.id}/cancel"
    expect(response).to have_http_status(:forbidden)
    expect(page.at_css("h1").text).to eq("Nothing was done")
    expect(task.reload.state).to eq("queued")
    post "/tasks/batches/#{task.task_batch_id}/cancel", params: { second_factor_code: "000000" }
    expect(response).to have_http_status(:forbidden)
    expect(task.reload.state).to eq("queued")
    expect(AuditEntry.where(action: Audit::Actions::SECOND_FACTOR_STEP_UP_FAILED).sole.changeset["purpose"]).to eq("cancel_task")
  end

  it "cancels another operator's queued task with a code and goes back where it came from" do
    host = task_host(name: "sim-028")
    task = create_task(host, operator: creator)
    post "/tasks/#{task.id}/cancel", params: code, headers: { "Referer" => "http://#{HostSeparation.dashboard_host}/audit" }
    expect(response).to redirect_to("http://#{HostSeparation.dashboard_host}/audit")
    expect(flash[:notice]).to eq("Task ##{task.id} cancelled. sim-028 will never run it.")
    expect(task.reload.state).to eq("cancelled")
    expect(AuditEntry.where(action: Audit::Actions::TASK_CANCELLED).sole).to have_attributes(actor_type: "operator", actor_id: operator.id)
  end

  it "says what a cancel of a running task did, and refuses a finished one" do
    stoppable = run(create_task(task_host, operator: creator))
    post "/tasks/#{stoppable.id}/cancel", params: code
    expect(response).to redirect_to("/")
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
  end
end
