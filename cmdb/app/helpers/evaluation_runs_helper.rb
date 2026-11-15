# Progress of a fleet-wide evaluation (#197), as plain text where it was triggered: the rule page after a rule change,
# the Advisory data sources page after an import. The line refreshes only itself (EvaluationRunsController#progress).
module EvaluationRunsHelper
  # The first delay before the line asks for itself again; it doubles each time, up to the last (review of #204).
  FIRST_REFRESH_SECONDS = 3
  LAST_REFRESH_SECONDS = 60
  # A run that has not moved for this long is shown as stalled, and the line stops asking.
  STALLED_AFTER = 10.minutes

  def evaluation_doing(run) = run.kind == "cis_rules" ? "Checking every host against the latest change" : "Re-matching the hosts the latest import affects"

  # "3,000 of 10,000 hosts done", or "starting" for a run not split yet.
  def evaluation_count_text(run)
    return "starting" if run.state == "queued"

    "#{number_with_delimiter(run.hosts_done)} of #{pluralize(number_with_delimiter(run.host_count), 'host')} done"
  end

  def evaluation_refresh_seconds(tick) = [ FIRST_REFRESH_SECONDS * (2**tick.clamp(0, 10)), LAST_REFRESH_SECONDS ].min

  def evaluation_stalled?(run) = run.updated_at < STALLED_AFTER.ago
end
