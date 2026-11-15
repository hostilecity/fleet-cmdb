# Expires tasks still waiting at their expiry, so they are never delivered (FR-3.2, P3-S05, AC-3.8). Scheduled
# every minute in config/recurring.yml.
class TaskExpiryJob < ApplicationJob
  queue_as :realtime # every minute; its own worker, so long jobs never delay it (S-7, config/queue.yml)

  def perform
    TaskLeases.expire!
  end
end
