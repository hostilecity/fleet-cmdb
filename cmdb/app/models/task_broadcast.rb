# Live task updates (P3-DASH-TASKS, FR-3.4): the task list, a task's page, batch progress, and a host's Tasks tab
# update without a reload when a task is created, changes state, records a cancel request, or reports progress, or
# when a late result arrives. Task and TaskLateResult call changed after their transaction commits, so a browser
# never sees uncommitted state. The refresh is a Turbo page refresh, as for the fleet pages, so each open page
# re-renders itself with its own filters, and batch counts are always worked out from the task rows (mockup Q14).
# LiveRefresh coalesces the refreshes: each stream at most once per window (#194).
#
# A task's change refreshes the task list (STREAM), its batch's page (batch_stream), and its host's pages, the
# task's own page among them (FleetBroadcast.host_stream). Other batches' and hosts' open pages do not refresh.
module TaskBroadcast
  STREAM = "tasks".freeze

  module_function

  def batch_stream(batch_id) = "tasks:batch:#{batch_id}"

  def changed(task)
    LiveRefresh.request([ STREAM, batch_stream(task.task_batch_id), FleetBroadcast.host_stream(task.host_id) ])
  end
end
