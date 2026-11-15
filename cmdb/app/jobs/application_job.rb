class ApplicationJob < ActiveJob::Base
  # No job fails silently (NFR-4, P1-O02). A job that raises is retried with a growing delay (about 3s, 18s, 83s,
  # then 4 minutes, with jitter), which covers a deadlock or a brief database or network fault. After the last
  # attempt the error is raised again, Solid Queue keeps the execution as failed, and the failure shows on the
  # dashboard banner, on the failed-jobs page, and in /health. Jobs that retry differently declare their own
  # retry_on, which takes precedence (AgentReleaseImportJob).
  ATTEMPTS = 5
  # Solid Queue runs a queue's lower numbers first; jobs that set none have 0. The live-refresh broadcasts share
  # the realtime queue with the every-minute jobs and wait behind them (S-7).
  BROADCAST_PRIORITY = 10

  retry_on StandardError, wait: :polynomially_longer, attempts: ATTEMPTS
end
