# The report ids already processed for a host, so a retried report is recognised (DEC-07). The receipt tables are
# partitioned by day (ADR 0027), and a unique (host_id, report_id) cannot be enforced across partitions. Every recorder
# holds the host's row lock (AgentHostLock) before it calls this, so "is there a receipt? then insert one" cannot race
# with another report for the same host. The lookup probes each partition's (host_id, report_id) index, and the rows of
# a default partition set aside to be moved back (Partitions.with_set_aside), so a retry is still recognised then.
module ReportReceipts
  module_function

  # Records the report id for the host and returns true, or returns false when it was recorded before (a duplicate).
  def record!(model, host_id:, report_id:, now:)
    return false if recorded?(model, host_id:, report_id:)

    model.insert!({ host_id:, report_id:, received_at: now })
    true
  end

  # One query in the usual case: the lookup, and whether a set-aside default exists, together (review 3 of #239, N6).
  # Only while one exists, which is rare and short, is it looked up as well.
  def recorded?(model, host_id:, report_id:)
    c = model.connection
    found, set_aside = c.select_rows(<<~SQL.squish).first
      SELECT EXISTS (#{model.where(host_id:, report_id:).select(1).to_sql}),
             pg_catalog.to_regclass(#{c.quote("public.#{Partitions.set_aside_name(model.table_name)}")}) IS NOT NULL
    SQL
    found || (set_aside && Partitions.with_set_aside(model).exists?(host_id:, report_id:))
  end
end
