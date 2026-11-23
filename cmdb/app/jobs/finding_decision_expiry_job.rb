# Ends finding decisions that no longer hold (VT-OVERRIDES #261, VT-S06), every hour: those past their last day
# (expired) and those whose evidence got worse than recorded (suspended), each audited as the system, and re-triages
# the findings they covered (FindingDecisions::Lifecycle.sweep!). A control already stops applying on the day after
# its last day, whatever this job's timing (FindingDecisions::ControlSource); this job makes the end visible and
# audited, and catches a worse signal no triage run re-triaged.
class FindingDecisionExpiryJob < ApplicationJob
  queue_as :default
  # A long sweep (a mass expiry) and the next hour's do not run side by side: the next one waits for it.
  limits_concurrency key: "finding_decision_expiry", duration: 3.hours

  def perform(now: Time.current)
    ended = FindingDecisions::Lifecycle.sweep!(now:)
    Rails.logger.info("[decisions] #{ended} finding decisions ended (expired or suspended)") if ended.positive?
    ended
  end
end
