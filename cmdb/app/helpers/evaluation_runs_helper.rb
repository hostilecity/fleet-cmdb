# Progress of a fleet-wide evaluation (#197), as plain text where it was triggered: the rule page after a rule change,
# the Advisory data sources page after an import.
module EvaluationRunsHelper
  # How often a page showing an unfinished run refreshes itself.
  PROGRESS_REFRESH_SECONDS = 3

  # "Checking every host against this rule: 3,000 of 10,000 hosts done." run: an unfinished EvaluationRun.
  def evaluation_progress_text(run, doing)
    return "#{doing}: starting." if run.state == "queued"

    "#{doing}: #{number_with_delimiter(run.hosts_done)} of #{pluralize(number_with_delimiter(run.host_count), 'host')} done."
  end
end
