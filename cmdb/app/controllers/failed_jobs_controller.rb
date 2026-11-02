# Failed background jobs (P1-O02): read-only, behind sign-in like every dashboard page (FR-S.4). A job
# appears here once it has failed all its retries (ApplicationJob). Error text comes from the failing code,
# so the view escapes it like any other text.
class FailedJobsController < ApplicationController
  def index
    @failures = JobHealth.failures
    @total = JobHealth.total_failed
    @window = JobHealth::RECENT
  end
end
