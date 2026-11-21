# Counts how many of a signal import's CVEs match open findings, after the import committed (Signals.count_matching!,
# reviews of #269), for the Data sources panels. Best effort: a statement past Signals::MATCHING_TIMEOUT is stored as
# "too large to count"; any other error is retried, and after the last attempt it is stored as "count failed" and logged.
# It is not raised again, since the import it counts for is stored and current; the panel shows the failure, and
# bin/rails signals:recount queues the count again.
class SignalMatchCountJob < ApplicationJob
  ATTEMPTS = 3

  queue_as :default

  retry_on StandardError, wait: :polynomially_longer, attempts: ATTEMPTS do |job, error|
    import = SignalImport.find_by(id: job.arguments.first)
    Signals.record_count_failure!(import, error) if import
  end

  def perform(import_id, added = nil)
    import = SignalImport.find_by(id: import_id) or return

    Signals.count_matching!(import, added:)
  end
end
