# Tells open task pages that a task changed (P3-DASH-TASKS). The message is a Turbo page refresh with no task data in
# it: each page re-requests itself and morphs the result in. Turbo debounces bursts, such as a batch created or
# cancelled at once.
class TaskBroadcastJob < ApplicationJob
  def perform
    Turbo::StreamsChannel.broadcast_refresh_to(TaskBroadcast::STREAM)
  end
end
