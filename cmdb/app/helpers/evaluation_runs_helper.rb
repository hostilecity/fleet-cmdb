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

  # "3,000 of 10,000 hosts done", or "starting" for a run not split yet.
  def evaluation_count_text(run)
    return "starting" if run.state == "queued"

    "#{number_with_delimiter(run.hosts_done)} of #{pluralize(number_with_delimiter(run.host_count), 'host')} done"
  end

  # Why a failed run stopped: a job that failed every retry, or (#278) one stopped again and again with no progress,
  # which Solid Queue records as a failed job too (a worker killed by a restart or for its memory).
  def evaluation_failure_text(run)
    return "Part of the work failed every retry" unless run.stopped?

    "Its work was stopped #{EvaluationRun::RESUMES + 1} times in a row with no progress, as when a job worker is " \
      "restarted or runs out of memory part way"
  end

  def evaluation_refresh_seconds(tick) = [ FIRST_REFRESH_SECONDS * (2**tick.clamp(0, 10)), LAST_REFRESH_SECONDS ].min

  def evaluation_stalled?(run) = run.updated_at < STALLED_AFTER.ago
end
