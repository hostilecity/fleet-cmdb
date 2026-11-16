# Opens a rollout's next stage once every host of stage `from` has confirmed (P1-UPDATES, #199). Enqueued after the
# commit that confirmed the stage, so the update result that confirmed it never waits while a large stage's hosts are
# chosen; Rollouts.advance_confirmed! chooses them without the rollout lock and then advances under it. Does nothing
# if the rollout moved on, halted, or was cancelled meanwhile. RolloutTimeoutJob runs the same check every minute in
# case this job is lost.
class RolloutAdvanceJob < ApplicationJob
  queue_as :default

  def perform(rollout_id, from)
    Rollouts.advance_confirmed!(rollout_id, from:)
  end
end
