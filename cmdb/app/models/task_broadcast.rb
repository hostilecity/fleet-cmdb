# Live task updates (P3-DASH-TASKS, FR-3.4): the task list, a task's page, batch progress, and a host's Tasks tab
# update without a reload when a task is created, changes state, records a cancel request, or reports progress, or
# when a late result arrives. Task and TaskLateResult call changed after their transaction commits, so a browser
# never sees uncommitted state; the job sends a Turbo page refresh, as FleetBroadcastJob does, so each open page
# re-renders itself with its own filters, and batch counts are always worked out from the task rows (mockup Q14).
module TaskBroadcast
  STREAM = "tasks".freeze

  module_function

  def changed = TaskBroadcastJob.perform_later
end
