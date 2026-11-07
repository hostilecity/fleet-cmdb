# Marks report requests that no report satisfied within ReportRequests::TTL as expired (P2-S03), so the host
# page shows that the agent never answered and the heartbeat stops asking. Scheduled every minute in
# config/recurring.yml.
class ReportRequestExpiryJob < ApplicationJob
  def perform
    ReportRequests.expire!
  end
end
