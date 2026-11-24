# Recounts the compliance summaries of hosts whose counts an advisory's new severity moved (#193, ADR 0026). The import
# queues them in host_compliance_recounts inside its own transaction and enqueues this after it commits, so a long
# import never holds their summary rows; this recounts them in short sorted batches, then refreshes open fleet pages
# once. Idempotent: an empty queue does nothing, and a retried run recounts what is left.
class ComplianceSummaryRecountJob < ApplicationJob
  queue_as :default

  def self.after_import = ActiveRecord.after_all_transactions_commit { perform_later }

  # The same for accepted risks recorded or ended (VT-SCORES #262, #298; the trigger queues their hosts): once a
  # transaction, however many decisions it writes (a sweep slice ends up to a hundred), after it commits.
  def self.after_decisions
    return if Thread.current[:compliance_recount_after_decisions]

    Thread.current[:compliance_recount_after_decisions] = true
    ApplicationRecord.current_transaction.after_rollback { Thread.current[:compliance_recount_after_decisions] = nil }
    ActiveRecord.after_all_transactions_commit do
      Thread.current[:compliance_recount_after_decisions] = nil
      perform_later
    end
  end

  def perform
    recounted = HostComplianceSummary.drain_recounts!
    FleetBroadcast.refresh if recounted.positive?
    recounted
  end
end
