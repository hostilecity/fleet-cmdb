# GET /health (P1-S11, P1-O01): unauthenticated and minimal, for monitoring and the operator's alerting. Answers
# 200 with {"status":"ok"} or 503 with {"status":"unhealthy"}, and names each check as ok or failing; it shows no
# versions, counts, paths, or error text (the log has the detail). Served on the agent hostname and localhost only,
# like /up, which stays the container's liveness check.
#
# - database: a query succeeds.
# - releases: the binaries of the newest release and of a running rollout's target are on disk with the
#   recorded size (Releases::StoreCheck).
# - backup: the last complete backup is recent enough (Backup::Status).
# - failed_jobs: no background job has failed all its retries in the last day (JobHealth, P1-O02).
# - job_liveness: the recurring liveness job has finished within the last few minutes, so the scheduler, a
#   worker, and the queue database are working (JobHealth).
class HealthController < ActionController::API
  CHECKS = {
    "database" => -> { ActiveRecord::Base.connection.select_value("SELECT 1") == 1 },
    "releases" => -> { Releases::StoreCheck.healthy? },
    "backup" => -> { Backup::Status.fresh? },
    "failed_jobs" => -> { !JobHealth.failing? },
    "job_liveness" => -> { JobHealth.liveness_recent? }
  }.freeze

  def show
    results = CHECKS.transform_values { |check| run(check) }
    healthy = results.values.all?
    response.set_header("Cache-Control", "no-store")
    render json: { status: healthy ? "ok" : "unhealthy", checks: results.transform_values { |ok| ok ? "ok" : "failing" } },
           status: healthy ? :ok : :service_unavailable
  end

  private

  def run(check)
    check.call
  rescue StandardError => e
    logger.error("[health] a check raised #{e.class}")
    false
  end
end
