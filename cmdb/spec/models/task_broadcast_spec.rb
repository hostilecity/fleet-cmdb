require "rails_helper"

# Live task pages (P3-DASH-TASKS, #194): a task's change refreshes the task list, its batch's page, and its host's
# pages, and nothing else. What happens to them then is LiveRefresh's (spec/services/live_refresh_spec.rb).
RSpec.describe TaskBroadcast do
  def streams_for(task) = [ described_class::STREAM, described_class.batch_stream(task.task_batch_id), FleetBroadcast.host_stream(task.host_id) ]

  it "refreshes after a task is created, changes state, records a cancel request or progress, or gets a late result, and not for a rollback" do
    hosts = [ task_host, task_host ]
    record_refresh_requests
    task = create_task(hosts.first)
    other = create_task(hosts.last)
    expect(refresh_requests).to eq([ streams_for(task), streams_for(other) ])
    expect(streams_for(task) & streams_for(other)).to eq([ described_class::STREAM ]) # another batch, another host

    refresh_requests.clear
    task.claim!(actor: task.host, lease_expires_at: 5.minutes.from_now)
    task.start!(actor: task.host, lease_expires_at: 1.hour.from_now)
    task.record_progress!(percent: 10)
    task.request_cancel!(operator: create(:operator))
    expect(refresh_requests).to eq([ streams_for(task) ] * 4)

    refresh_requests.clear
    Task.transaction do
      task.time_out!(actor: Audit::SYSTEM)
      raise ActiveRecord::Rollback
    end
    expect(refresh_requests).to eq([])

    task.reload.time_out!(actor: Audit::SYSTEM)
    refresh_requests.clear
    payload = { "report_id" => SecureRandom.uuid, "outcome" => "succeeded", "exit_status" => 0, "started_at" => Time.current.iso8601, "finished_at" => Time.current.iso8601 }
    Task.transaction { AgentTasks.record_result!(host: task.host, task:, payload:) }
    expect(refresh_requests).to eq([ streams_for(task) ])
  end
end
