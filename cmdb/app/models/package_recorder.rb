# Stores a package report for an agent's host (P2-S08, FR-2.3, DEC-07). Runs inside the request transaction,
# under the host row lock (AgentHostLock), like InventoryRecorder, so concurrent reports for one host are
# serialised and a revocation that lands mid-request is still refused.
#
# - A report id already processed for the host is a duplicate: nothing changes.
# - When the content hash differs from the current set's, the list is stored in content-addressed chunks
#   (PackageStore, ADR 0028: only chunks and a set not stored yet are written), the host points at its PackageSet, and a
#   snapshot naming the set is written. Otherwise only the report details (time, warnings) are updated.
# - An unsupported package manager is stored as such, with its reason and no packages: never as an empty set.
# - An unreadable one (dpkg is there, its database could not be listed) is stored with its reason too, but the
#   host's previous set and count are kept (its snapshot names no set), since nothing says they changed; vulnerability matching does not
#   evaluate the host meanwhile (HostContext), so its findings stay as they were.
# - Skipped packages (named by the agent, not listed as installed) are stored with the set and its snapshot; they
#   are not in the PackageSet, so findings for them resolve as removed at the next matching, and reopen when the
#   package is listed again (P2-S08, P2-S11 owner decision).
# - A new report, changed or not, satisfies the host's pending packages report request (ReportRequests, P2-S03).
# - What is in use (in_use, FR-2.6) goes to HostApplicability, written only when it changes; a report without it
#   (unreadable and unsupported ones included) clears it.
#
# Vulnerability matching (P2-S11) runs after a new snapshot, for that host, once the transaction commits.
module PackageRecorder
  Result = Data.define(:report_id, :duplicate, :snapshot)

  module_function

  def record!(host_id:, credential_id:, report:)
    host = AgentHostLock.lock!(host_id:, credential_id:)
    now = Time.current
    unless ReportReceipts.record!(PackageReportReceipt, host_id:, report_id: report.report_id, now:) # under the host lock (ADR 0027)
      return Result.new(report_id: report.report_id, duplicate: true, snapshot: false)
    end

    ReportRequests.satisfy!(host:, report_type: "packages", report:, now:) # an operator's request (P2-S03)
    set = HostPackageSet.find_or_initialize_by(host_id:)
    hash = report.content_hash
    snapshot = set.content_hash != hash
    if snapshot
      package_set_id = report.manager == "dpkg" ? PackageStore.store!(report.packages, now:) : nil
      PackageSnapshot.create!(host_id:, manager: report.manager, unsupported_reason: report.unsupported_reason,
                              package_count: report.packages.size, content_hash: hash, package_set_id:,
                              skipped: report.skipped.map(&:to_h), warnings: report.warnings, report_id: report.report_id, collected_at: report.collected_at, received_at: now)
      set.package_set_id = package_set_id unless report.unreadable?
      VulnerabilityMatchJob.after_snapshot(host_id)
    end
    set.update!(manager: report.manager, unsupported_reason: report.unsupported_reason, package_count: report.unreadable? ? set.package_count.to_i : report.packages.size,
                content_hash: hash, skipped: report.skipped.map(&:to_h), warnings: report.warnings, report_id: report.report_id, schema_version: report.schema_version,
                collected_at: report.collected_at, received_at: now)
    HostApplicability.record_in_use!(host_id:, report:, now:) # what is in use (FR-2.6, #258), written only when it changes
    Result.new(report_id: report.report_id, duplicate: false, snapshot:)
  end
end
