# GET /health (P1-S11, P1-O01): unauthenticated and minimal, for monitoring and the operator's alerting. Answers
# 200 with {"status":"ok"} or 503 with {"status":"unhealthy"}, and names each check as ok, warning, or failing; it
# shows no versions, counts, paths, or error text (the log has the detail). A warning does not make the status
# unhealthy: it is something to fix that has not stopped anything yet. Served on the agent hostname and localhost
# only, like /up, which stays the container's liveness check.
#
# - database: a query succeeds.
# - releases: the binaries of the newest release and of a running rollout's target are on disk with the
#   recorded size (Releases::StoreCheck).
# - backup: the last complete backup is recent enough (Backup::Status).
# - failed_jobs: no background job has failed all its retries in the last day (JobHealth, P1-O02).
# - job_liveness: the recurring liveness job has finished within the last few minutes, so the scheduler, a
#   worker, and the queue database are working (JobHealth).
# - live_updates: this process's Solid Cable listener, once started, is still running (CableHealth, #194). With
#   several Puma processes, each answers for itself.
# - partitions: the history tables' partitions (ADR 0027, #195). Failing when the audit log has fewer than 2 months
#   of partitions ahead (it has no default partition, so audited actions would start failing); a warning when a
#   default partition has rows, fewer than 2 partitions are ahead, or a partition has been due for retirement, or
#   missing ahead, for 3 days (Partitions.health).
# - audit_guard: a warning until the PostgreSQL superuser has installed the audit log's event triggers and taken the
#   guard function (ops/postgres/audit-guard.sql); the app works without them.
class HealthController < ActionController::API
  CHECKS = {
    "database" => -> { ActiveRecord::Base.connection.select_value("SELECT 1") == 1 },
    "releases" => -> { Releases::StoreCheck.healthy? },
    "backup" => -> { Backup::Status.fresh? },
    "failed_jobs" => -> { !JobHealth.failing? },
    "job_liveness" => -> { JobHealth.liveness_recent? },
    "live_updates" => -> { CableHealth.listening? },
    "partitions" => -> { { ok: true, warning: :warning, failing: false }.fetch(Partitions.health) },
    "audit_guard" => -> { Partitions.audit_guard_installed? || :warning }
  }.freeze
  STATES = { true => "ok", warning: "warning", false => "failing" }.freeze

  def show
    results = CHECKS.transform_values { |check| run(check) }
    healthy = results.values.none?(false)
    response.set_header("Cache-Control", "no-store")
    render json: { status: healthy ? "ok" : "unhealthy", checks: results.transform_values { |state| STATES.fetch(state) } },
           status: healthy ? :ok : :service_unavailable
  end

  private

  # true, :warning, or false (anything else a check returns counts as true or false).
  def run(check)
    state = check.call
    state == :warning ? state : !!state
  rescue StandardError => e
    logger.error("[health] a check raised #{e.class}")
    false
  end
end
