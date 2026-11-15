# Marks hosts that never confirmed an update as unconfirmed and halts their rollout (P1-UPDATES, AC-1.10).
# Scheduled every minute in config/recurring.yml.
class RolloutTimeoutJob < ApplicationJob
  queue_as :realtime # every minute; its own worker, so long jobs never delay it (S-7, config/queue.yml)

  def perform
    Rollouts.expire_unconfirmed!
  end
end
