# Ends task leases that ran out (FR-3.2, P3-S05, AC-3.5): a claim the agent never started goes back to the queue; a
# running task with no result after its deadline and grace is timed out, or failed with lease_expired if its agent
# went quiet. Scheduled every minute in config/recurring.yml.
class TaskLeaseJob < ApplicationJob
  queue_as :realtime # every minute; its own worker, so long jobs never delay it (S-7, config/queue.yml)

  def perform
    TaskLeases.lapse!
  end
end
