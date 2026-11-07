# Stores a package report for an agent's host (P2-S08, FR-2.3, DEC-07). Runs inside the request transaction,
# under the host row lock (AgentHostLock), like InventoryRecorder, so concurrent reports for one host are
# serialised and a revocation that lands mid-request is still refused.
#
# - A report id already processed for the host is a duplicate: nothing changes.
# - When the content hash differs from the current set's, a snapshot of the whole set is written and the
#   host's HostPackage rows are replaced. Otherwise only the report details (time, warnings) are updated.
# - An unsupported package manager is stored as such, with its reason and no packages: never as an empty set.
# - An unreadable one (dpkg is there, its database could not be listed) is stored with its reason too, but the
#   host's previous packages and count are kept, since nothing says they changed; vulnerability matching does not
#   evaluate the host meanwhile (HostContext), so its findings stay as they were.
# - Skipped packages (named by the agent, not listed as installed) are stored with the set and its snapshot; they
#   are not in HostPackage, so findings for them resolve as removed at the next matching (P2-S08 owner question).
# - A new report, changed or not, satisfies the host's pending packages report request (ReportRequests, P2-S03).
#
# Vulnerability matching (P2-S11) runs after a new snapshot, for that host, once the transaction commits.
module PackageRecorder
  Result = Data.define(:report_id, :duplicate, :snapshot)

  INSERT_BATCH = 5_000

  module_function

  def record!(host_id:, credential_id:, report:)
    host = AgentHostLock.lock!(host_id:, credential_id:)
    now = Time.current
    inserted = PackageReportReceipt.insert_all([ { host_id:, report_id: report.report_id, received_at: now } ],
                                               unique_by: %i[host_id report_id], returning: :id)
    return Result.new(report_id: report.report_id, duplicate: true, snapshot: false) if inserted.rows.empty?

    ReportRequests.satisfy!(host:, report_type: "packages", report:, now:) # an operator's request (P2-S03)
    set = HostPackageSet.find_or_initialize_by(host_id:)
    hash = report.content_hash
    snapshot = set.content_hash != hash
    if snapshot
      PackageSnapshot.create!(host_id:, manager: report.manager, unsupported_reason: report.unsupported_reason,
                              package_count: report.packages.size, content_hash: hash, packages: report.packages.map(&:to_a),
                              skipped: report.skipped.map(&:to_h), warnings: report.warnings, report_id: report.report_id, collected_at: report.collected_at, received_at: now)
      replace_packages(host_id, report.packages) unless report.unreadable?
      VulnerabilityMatchJob.after_snapshot(host_id)
    end
    set.update!(manager: report.manager, unsupported_reason: report.unsupported_reason, package_count: report.unreadable? ? set.package_count.to_i : report.packages.size,
                content_hash: hash, skipped: report.skipped.map(&:to_h), warnings: report.warnings, report_id: report.report_id, schema_version: report.schema_version,
                collected_at: report.collected_at, received_at: now)
    Result.new(report_id: report.report_id, duplicate: false, snapshot:)
  end

  def replace_packages(host_id, packages)
    HostPackage.where(host_id:).delete_all
    packages.each_slice(INSERT_BATCH) do |slice|
      HostPackage.insert_all(slice.map { |p| { host_id:, name: p.name, architecture: p.architecture, version: p.version, source: p.source } })
    end
  end
  private_class_method :replace_packages
end
