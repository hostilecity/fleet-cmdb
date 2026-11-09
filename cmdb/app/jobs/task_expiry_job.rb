# Expires tasks still waiting at their expiry, so they are never delivered (FR-3.2, P3-S05, AC-3.8). Scheduled
# every minute in config/recurring.yml.
class TaskExpiryJob < ApplicationJob
  def perform
    TaskLeases.expire!
  end
end
