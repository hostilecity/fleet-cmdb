# Sends the pending live refreshes (#194, LiveRefresh.flush): one Turbo page refresh to each stream that changed
# since the last flush. Enqueued by the change that starts a refresh window, to run at its end; never more than one
# is scheduled at a time.
class LiveRefreshJob < ApplicationJob
  # Open pages refresh within seconds, never behind a long import (S-7, config/queue.yml). After the every-minute
  # jobs on the same queue (a larger number runs later).
  queue_as :realtime
  queue_with_priority ApplicationJob::BROADCAST_PRIORITY

  # Short retries of its own (review of #218): a failed flush keeps the marker, so its retry is the only next flush,
  # but only while the marker is younger than its takeover age (the window plus LiveRefresh::ABANDONED_AFTER). The
  # default waits (83 s, 4 minutes) outlast that, so each takeover started another chain. Four retries 5 s apart end
  # within about 20 s. After the last one the job fails, shows on the failed-jobs page, and the sweep takes over.
  ATTEMPTS = 5
  retry_on StandardError, wait: 5.seconds, attempts: ATTEMPTS

  def perform
    streams = LiveRefresh.flush
    logger.info("[live_refresh] refreshed #{streams.size} #{'stream'.pluralize(streams.size)}: #{streams.first(10).join(',')}#{',...' if streams.size > 10}")
  end
end
