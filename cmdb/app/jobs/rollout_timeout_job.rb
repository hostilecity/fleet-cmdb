# Marks hosts that never confirmed an update as unconfirmed and halts their rollout (P1-UPDATES, AC-1.10), and enqueues
# RolloutAdvanceJob again for a running rollout whose stage has confirmed, in case that job was lost (#199). It never
# chooses a stage's hosts itself, so this queue is never held up (review of #215). Scheduled every minute in
# config/recurring.yml.
class RolloutTimeoutJob < ApplicationJob
  queue_as :realtime # every minute; its own worker, so long jobs never delay it (S-7, config/queue.yml)

  def perform
    Rollouts.expire_unconfirmed!
    Rollouts.advance_confirmed_stages!
  end
end
