# The report ids already processed for a host, so a retried report is recognised (DEC-07). The receipt tables are
# partitioned by day (ADR 0027), and a unique (host_id, report_id) cannot be enforced across partitions. Every recorder
# holds the host's row lock (AgentHostLock) before it calls this, so "is there a receipt? then insert one" cannot race
# with another report for the same host. The lookup probes each partition's (host_id, report_id) index, and the rows of
# a default partition set aside to be moved back (Partitions.with_set_aside), so a retry is still recognised then.
module ReportReceipts
  module_function

  # Records the report id for the host and returns true, or returns false when it was recorded before (a duplicate).
  def record!(model, host_id:, report_id:, now:)
    return false if Partitions.with_set_aside(model).exists?(host_id:, report_id:)

    model.insert!({ host_id:, report_id:, received_at: now })
    true
  end
end
