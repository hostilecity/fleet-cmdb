# Progress of a fleet-wide evaluation (#197), as plain text where it was triggered: the rule page after a rule change,
# the Advisory data sources page after an import. The line refreshes only itself (EvaluationRunsController#progress).
module EvaluationRunsHelper
  # The first delay before the line asks for itself again; it doubles each time, up to the last (review of #204).
  FIRST_REFRESH_SECONDS = 3
  LAST_REFRESH_SECONDS = 60
  # A run that has not moved for this long is shown as stalled, and the line stops asking.
  STALLED_AFTER = 10.minutes

  # An advisories run comes from an import, unless an upgrade or an operator started it because how packages are
  # matched changed (scope "reason" => "matching", #270: RematchSignedSources, bin/rails vulnerabilities:rematch).
  def evaluation_doing(run)
    return "Checking every host against the latest change" if run.kind == "cis_rules"
    return "Re-matching the hosts a change to how packages are matched affects" if run.scope["reason"] == "matching"
    return "Re-triaging every host's findings" if run.kind == "triage" && run.work.full?
    return "Re-triaging the hosts whose findings' exploitation signals or Debian triage changed" if run.kind == "triage"

    "Re-matching the hosts the latest import affects"
  end

  # A failed run's button and the notice after it is pressed, by kind: [starting over, carrying on from the batches it
  # had left] (review of #292: a run with batches left carries on, EvaluationRun.retry!).
  RETRY_TEXT = {
    "cis_rules" => [ [ "Check every host again", "Checking every host again." ], [ "Check the remaining hosts", "Checking the hosts that were left." ] ],
    "advisories" => [ [ "Re-match again", "Re-matching the affected hosts again." ], [ "Re-match the remaining hosts", "Re-matching the hosts that were left." ] ],
    "triage" => [ [ "Re-triage again", "Re-triaging the affected hosts again." ], [ "Re-triage the remaining hosts", "Re-triaging the hosts that were left." ] ]
  }.freeze

  def evaluation_retry_label(run) = RETRY_TEXT.fetch(run.kind)[run.carries_on? ? 1 : 0].first

  # "3,000 of 10,000 hosts done", "starting" for a run not split yet, or, for one that stopped before it was split
  # (review of #292: stopped while it was being prepared), "before its hosts were found".
  def evaluation_count_text(run)
    return "starting" if run.state == "queued"
    return "before its hosts were found" if run.failed? && run.started_at.nil?

    "#{number_with_delimiter(run.hosts_done)} of #{pluralize(number_with_delimiter(run.host_count), 'host')} done"
  end

  # Why a failed run stopped: a job that failed every retry, or (#278) one stopped again and again with no progress,
  # which Solid Queue records as a failed job too (a worker killed by a restart or for its memory). The first of the
  # RESUMES + 1 stops may follow progress; none after it did (review of #292).
  def evaluation_failure_text(run)
    return "Part of the work failed every retry" unless run.stopped?

    "Its work was stopped #{EvaluationRun::RESUMES + 1} times, with no progress after the first, as when a job worker " \
      "is restarted or runs out of memory part way"
  end

  # What to do before pressing the button, for a run the watch stopped: the same worker would most likely stop again.
  def evaluation_next_step(run) = run.stopped? ? "Check the job workers' memory and restarts, then start it again." : nil

  def evaluation_refresh_seconds(tick) = [ FIRST_REFRESH_SECONDS * (2**tick.clamp(0, 10)), LAST_REFRESH_SECONDS ].min

  def evaluation_stalled?(run) = run.updated_at < STALLED_AFTER.ago
end
