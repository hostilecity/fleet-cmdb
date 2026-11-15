# Sends the pending live refreshes (#194, LiveRefresh.flush): one Turbo page refresh to each stream that changed
# since the last flush. Enqueued by the change that starts a refresh window, to run at its end; never more than one
# is scheduled at a time.
class LiveRefreshJob < ApplicationJob
  # Open pages refresh within seconds, never behind a long import (S-7, config/queue.yml). After the every-minute
  # jobs on the same queue (a larger number runs later).
  queue_as :realtime
  queue_with_priority ApplicationJob::BROADCAST_PRIORITY

  def perform
    streams = LiveRefresh.flush
    logger.info("[live_refresh] refreshed #{streams.size} #{'stream'.pluralize(streams.size)}: #{streams.first(10).join(',')}#{',...' if streams.size > 10}")
  end
end
