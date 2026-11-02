# GET /health (P1-S11, P1-O01): unauthenticated and minimal, for monitoring and the operator's alerting. Answers
# 200 with {"status":"ok"} or 503 with {"status":"unhealthy"}, and names each check as ok or failing; it shows no
# versions, counts, paths, or error text (the log has the detail). Served on the agent hostname and localhost only,
# like /up, which stays the container's liveness check.
#
# - database: a query succeeds.
# - releases: the newest release's binary is on disk with the recorded size (Releases::StoreCheck).
# - backup: the last complete backup is recent enough (Backup::Status).
#
# Background job liveness joins these with P1-S11's remaining scope and P1-O02.
class HealthController < ActionController::API
  CHECKS = {
    "database" => -> { ActiveRecord::Base.connection.select_value("SELECT 1") == 1 },
    "releases" => -> { Releases::StoreCheck.healthy? },
    "backup" => -> { Backup::Status.fresh? }
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
