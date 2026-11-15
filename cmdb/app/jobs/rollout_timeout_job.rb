# Marks hosts that never confirmed an update as unconfirmed and halts their rollout (P1-UPDATES, AC-1.10), and opens
# the next stage of a running rollout whose stage has confirmed if its RolloutAdvanceJob was lost (#199). Scheduled
# every minute in config/recurring.yml.
class RolloutTimeoutJob < ApplicationJob
  queue_as :realtime # every minute; its own worker, so long jobs never delay it (S-7, config/queue.yml)

  def perform
    Rollouts.expire_unconfirmed!
    Rollouts.advance_confirmed_stages!
  end
end
