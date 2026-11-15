# The progress of a fleet-wide evaluation run (#197; review of #204), shown on the rule page and on Advisory data
# sources inside the evaluation_progress frame.
#
# - progress: the frame alone, so a tick reloads one line, not the whole page. It is asked for again after a delay
#   that doubles each time, from 3 s up to a minute, while the run is unfinished and moving; it stops when the run
#   is failed or has not moved for STALLED_AFTER. When the run is done, the frame reloads the page once, to show the
#   results. A tick does not count as the operator's activity, so an open tab cannot keep a session alive.
# - retry: a failed run is started again with the same rules or sources (a POST, CSRF-protected). The new run
#   supersedes the failed one. Starting evaluation changes no setting and contacts no agent, so it is not audited,
#   as the runs a rule change or an import start are not.
class EvaluationRunsController < ApplicationController
  def progress
    @run = EvaluationRun.find(params[:id])
    @tick = params[:tick].to_s.match?(/\A\d{1,2}\z/) ? params[:tick].to_i : 0
    render partial: "evaluation_runs/progress", locals: { run: @run, tick: @tick }
  end

  def retry
    run = EvaluationRun.find(params[:id])
    return redirect_to(page_for(run), alert: "That run did not fail, so there is nothing to start again.") unless run.failed?

    EvaluationRun.start!(run.kind, run.scope)
    redirect_to page_for(run), notice: run.kind == "cis_rules" ? "Checking every host again." : "Re-matching the affected hosts again."
  end

  private

  def records_activity? = action_name != "progress"

  # The page the run's progress is shown on: its rule's (the first, for a rules file import), or Data sources.
  def page_for(run)
    return data_sources_path if run.kind == "advisories"

    rule = CisRule.find_by(id: Array(run.scope["rule_ids"]).first)
    rule ? rule_path(rule) : rules_path
  end
end
