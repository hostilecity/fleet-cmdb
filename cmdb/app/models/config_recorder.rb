# Stores a config report for an agent's host (P2-S02, FR-2.1, DEC-07). Runs inside the request transaction,
# under the host row lock (AgentHostLock), like PackageRecorder, so concurrent reports for one host are
# serialised and a revocation that lands mid-request is still refused.
#
# - A report id already processed for the host is a duplicate: nothing changes.
# - When the content hash differs from the current facts', a snapshot is written. Otherwise only the report
#   details (times, manifest version, ignored keys) are updated.
#
# Rule evaluation (P2-S06) runs after a new snapshot; it is added with that section.
module ConfigRecorder
  Result = Data.define(:report_id, :duplicate, :snapshot)

  module_function

  def record!(host_id:, credential_id:, report:)
    AgentHostLock.lock!(host_id:, credential_id:)
    now = Time.current
    inserted = ConfigReportReceipt.insert_all([ { host_id:, report_id: report.report_id, received_at: now } ],
                                              unique_by: %i[host_id report_id], returning: :id)
    return Result.new(report_id: report.report_id, duplicate: true, snapshot: false) if inserted.rows.empty?

    current = HostConfig.find_or_initialize_by(host_id:)
    hash = report.content_hash
    snapshot = current.content_hash != hash
    details = { facts: report.facts, content_hash: hash, state_counts: report.counts, manifest_version: report.manifest_version,
                report_id: report.report_id, collected_at: report.collected_at, received_at: now }
    ConfigSnapshot.create!(host_id:, **details) if snapshot
    current.update!(**details, ignored_keys: report.ignored_keys.first(AgentApi::ConfigReport::MAX_IGNORED), schema_version: report.schema_version)
    Result.new(report_id: report.report_id, duplicate: false, snapshot:)
  end
end
