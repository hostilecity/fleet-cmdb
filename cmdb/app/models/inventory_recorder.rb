# Stores an inventory report for an agent's host (P1-INVENTORY, FR-1.3, DEC-07, FR-S.1). Runs inside the
# request transaction, under the host row lock (AgentHostLock), so concurrent reports for one host are
# serialised and a revocation or re-enrollment that lands mid-request is still refused.
#
# - A report id already processed for the host is a duplicate: nothing changes (idempotency, layer 1).
# - The current inventory is replaced on every report; a snapshot is written only when the stable-field
#   hash changes (layer 2), which includes boot id changes, so reboots are visible.
# - A machine id different from the one the credential was enrolled with sets a visible warning on the host
#   and is audited once; the first inventory is audited too. Ordinary reports write no audit entries.
module InventoryRecorder
  Result = Data.define(:report_id, :duplicate, :snapshot)

  module_function

  def record!(host_id:, credential_id:, report:)
    host = AgentHostLock.lock!(host_id:, credential_id:)
    now = Time.current
    inserted = InventoryReportReceipt.insert_all([ { host_id:, report_id: report.report_id, received_at: now } ],
                                                 unique_by: %i[host_id report_id], returning: :id)
    return Result.new(report_id: report.report_id, duplicate: true, snapshot: false) if inserted.rows.empty?

    inventory = HostInventory.find_or_initialize_by(host_id:)
    first = inventory.new_record?
    hash = report.stable_hash
    snapshot = inventory.stable_hash != hash
    if snapshot
      InventorySnapshot.create!(host_id:, stable: report.stable, warnings: report.warnings, stable_hash: hash,
                                report_id: report.report_id, collected_at: report.collected_at, received_at: now)
    end
    inventory.update!(stable: report.stable, volatile: report.volatile, warnings: report.warnings, stable_hash: hash,
                      report_id: report.report_id, schema_version: report.schema_version,
                      collected_at: report.collected_at, received_at: now)

    if first
      Audit.record(actor: host, action: Audit::Actions::HOST_FIRST_INVENTORY, target: host,
                   changes: { "stable_hash" => [ nil, hash ] })
    end
    check_machine_id(host, credential_id, report.machine_id, now)
    Result.new(report_id: report.report_id, duplicate: false, snapshot:)
  end

  # FR-S.1 clone detection. The credential records the machine id seen at enrollment (or, when it was
  # unreadable then, the first one reported). A different one sets the host warning, audited only when it
  # changes, so a cloned VM is visible without an entry per report.
  def check_machine_id(host, credential_id, reported, now)
    return if reported.nil?

    credential = AgentCredential.find(credential_id)
    if credential.machine_id.nil?
      credential.update_column(:machine_id, reported)
    elsif credential.machine_id != reported && host.reported_machine_id != reported
      Host.where(id: host.id).update_all(machine_id_mismatch_at: now, reported_machine_id: reported)
      Audit.record(actor: host, action: Audit::Actions::HOST_MACHINE_ID_MISMATCH, target: host,
                   changes: { "machine_id" => [ credential.machine_id, reported ] })
    end
  end
  private_class_method :check_machine_id
end
