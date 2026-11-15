# Every minute (config/recurring.yml): schedules a live-refresh flush for streams left pending with no flush coming,
# because a flush job was lost, discarded after its retries, or never enqueued, and no change has arrived since to
# take its marker over (LiveRefresh.sweep, review of #212). Usually finds nothing: one indexed query.
class LiveRefreshSweepJob < ApplicationJob
  queue_as :realtime
  queue_with_priority ApplicationJob::BROADCAST_PRIORITY

  def perform
    logger.info("[live_refresh] sweep scheduled a flush for streams left pending") if LiveRefresh.sweep
  end
end
