# Tells open task pages that a task changed (P3-DASH-TASKS). The message is a Turbo page refresh with no task data in
# it: each page re-requests itself and morphs the result in. Turbo debounces bursts, such as a batch created or
# cancelled at once.
class TaskBroadcastJob < ApplicationJob
  # Open pages refresh within seconds, never behind a long import (S-7, config/queue.yml). After the every-minute
  # jobs on the same queue (a larger number runs later), so a burst of changes cannot hold them up. A burst still
  # queues one refresh per change; coalescing them is #194.
  queue_as :realtime
  queue_with_priority ApplicationJob::BROADCAST_PRIORITY

  def perform
    Turbo::StreamsChannel.broadcast_refresh_to(TaskBroadcast::STREAM)
  end
end
