require "rails_helper"

# Live task pages (P3-DASH-TASKS): batch counts and rows update without a reload. What is broadcast, and when.
RSpec.describe TaskBroadcastJob, type: :job do
  include ActiveJob::TestHelper

  def broadcasts = ActionCable.server.pubsub.broadcasts(TaskBroadcast::STREAM)

  def enqueued = enqueued_jobs.count { |job| job["job_class"] == "TaskBroadcastJob" }

  before { ActionCable.server.pubsub.clear }

  it "sends one Turbo page refresh to the tasks stream, with no task data in it" do
    create_task(task_host).cancel!(actor: Audit::SYSTEM)
    described_class.perform_now
    expect(broadcasts.size).to eq(1)
    message = JSON.parse(broadcasts.first)
    expect(Nokogiri::HTML.fragment(message).css("turbo-stream").map { |stream| stream["action"] }).to eq([ "refresh" ])
  end

  it "is enqueued after a task is created, changes state, records a cancel request or progress, or gets a late result, and not for a rollback" do
    task = create_task(task_host)
    expect(enqueued).to eq(1)
    clear_enqueued_jobs
    task.claim!(actor: task.host, lease_expires_at: 5.minutes.from_now)
    task.start!(actor: task.host, lease_expires_at: 1.hour.from_now)
    task.record_progress!(percent: 10)
    task.request_cancel!(operator: create(:operator))
    expect(enqueued).to eq(4)
    clear_enqueued_jobs

    Task.transaction do
      task.time_out!(actor: Audit::SYSTEM)
      raise ActiveRecord::Rollback
    end
    expect(enqueued).to eq(0)

    task.reload.time_out!(actor: Audit::SYSTEM)
    clear_enqueued_jobs
    payload = { "report_id" => SecureRandom.uuid, "outcome" => "succeeded", "exit_status" => 0, "started_at" => Time.current.iso8601, "finished_at" => Time.current.iso8601 }
    Task.transaction { AgentTasks.record_result!(host: task.host, task:, payload:) }
    expect(enqueued).to eq(1)
  end
end
