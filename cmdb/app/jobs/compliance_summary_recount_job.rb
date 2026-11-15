# Recounts the compliance summaries of hosts whose counts an advisory's new severity moved (#193, ADR 0026). The import
# queues them in host_compliance_recounts inside its own transaction and enqueues this after it commits, so a long
# import never holds their summary rows; this recounts them in short sorted batches, then refreshes open fleet pages
# once. Idempotent: an empty queue does nothing, and a retried run recounts what is left.
class ComplianceSummaryRecountJob < ApplicationJob
  queue_as :default

  def self.after_import = ActiveRecord.after_all_transactions_commit { perform_later }

  def perform
    recounted = HostComplianceSummary.drain_recounts!
    FleetBroadcast.refresh if recounted.positive?
    recounted
  end
end
