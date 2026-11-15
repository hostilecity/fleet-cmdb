# Marks report requests that no report satisfied within ReportRequests::TTL as expired (P2-S03), so the host
# page shows that the agent never answered and the heartbeat stops asking. Scheduled every minute in
# config/recurring.yml.
class ReportRequestExpiryJob < ApplicationJob
  queue_as :realtime # every minute; its own worker, so long jobs never delay it (S-7, config/queue.yml)

  def perform
    ReportRequests.expire!
  end
end
