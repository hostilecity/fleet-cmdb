# Why each of a host's CIS-aligned results changed (P2-D02, FR-2.2): the change history the Configuration tab and the
# snapshot comparison show, each CisResultChange with its cause. A change names the rule version and the config
# snapshot that produced it (P2-S06) but not why the evaluation ran, so the cause is worked out from the change
# before it for the same rule:
#
#   first         the rule's first result on the host
#   report        a new config snapshot (the snapshot differs from the one before, and arrived after the rule
#                 version did), with the rule's fact before and after it
#   rule_edited   a new rule version (an edit re-evaluates every host with no agent contact)
#   rule_enabled  the result left not evaluated with no new snapshot
#   rule_disabled the result became not evaluated because the rule was disabled
#   reevaluated   anything else, such as a change of the host's operating system
#
# An operator's edit, enable, or disable is named with who did it, from the audit log. A fixed number of queries
# whatever the number of changes.
class CisResultHistory
  Entry = Data.define(:change, :rule_key, :cause, :fact, :before, :after, :version, :actor, :first_report) do
    def snapshot_id = change.config_snapshot_id
    def from = change.from_result
    def to = change.to_result
    def occurred_at = change.occurred_at
  end

  AUDITED = { Audit::Actions::RULE_EDITED => :rule_edited, Audit::Actions::RULE_ENABLED => :rule_enabled, Audit::Actions::RULE_DISABLED => :rule_disabled }.freeze

  def initialize(host_id)
    @host_id = host_id
  end

  # The newest changes, newest first; limit nil for all.
  def latest(limit) = explain(changes.order(occurred_at: :desc, id: :desc).limit(limit))

  # Every change produced from one of these snapshots, oldest first.
  def for_snapshots(snapshot_ids) = explain(changes.where(config_snapshot_id: snapshot_ids).order(:occurred_at, :id))

  # Every change that occurred in the time range, oldest first.
  def during(range) = explain(changes.where(occurred_at: range).order(:occurred_at, :id))

  private

  # The host's changes, each with the snapshot, version, and time of the change before it for the same rule.
  def changes
    window = "OVER (PARTITION BY cis_rule_id ORDER BY occurred_at, id)"
    inner = CisResultChange.where(host_id: @host_id)
                           .select("cis_result_changes.*", "lag(config_snapshot_id) #{window} AS prev_snapshot_id",
                                   "lag(cis_rule_version_id) #{window} AS prev_version_id", "lag(occurred_at) #{window} AS prev_occurred_at",
                                   "lag(reason) #{window} AS prev_reason")
    CisResultChange.from(inner, :cis_result_changes)
  end

  def explain(scope)
    rows = scope.to_a
    return [] if rows.empty?

    keys = CisRule.where(id: rows.map(&:cis_rule_id)).pluck(:id, :key).to_h
    versions = CisRuleVersion.where(id: rows.map(&:cis_rule_version_id).compact).index_by(&:id)
    snapshots = snapshot_facts(rows.map(&:config_snapshot_id).compact.uniq)
    audits = audit_entries(keys.keys)
    rows.map { |change| entry(change, keys, versions[change.cis_rule_version_id], snapshots, audits) }
  end

  def entry(change, keys, version, snapshots, audits)
    snapshot = snapshots[change.config_snapshot_id]
    cause = cause(change, snapshot, version)
    fact = version&.fact
    before, after = (snapshot && fact) ? [ snapshot[:previous_facts]&.dig(fact), snapshot[:facts][fact] ] : []
    Entry.new(change:, rule_key: keys[change.cis_rule_id], cause:, fact:, before:, after:, version: version&.version,
              actor: actor(audits, change, cause, version), first_report: snapshot.present? && snapshot[:previous_facts].nil?)
  end

  def cause(change, snapshot, version)
    return :first if change.from_result.nil?
    return :rule_disabled if change.to_result == "not_evaluated" && change.reason == CisEvaluation::DISABLED
    return :reevaluated if snapshot.nil? || version.nil?

    prev_at = change[:prev_occurred_at]
    if change.from_result == "not_evaluated" # enabled again, or the host's first report after none
      # The reason it was not evaluated says which; a report that arrived while the rule was disabled does not make
      # the enable a report's doing (review of #118). Times decide only when the change before was pruned.
      return :rule_enabled if change[:prev_reason] == CisEvaluation::DISABLED
      return :report if change[:prev_reason] == CisEvaluation::NO_REPORT

      return prev_at.nil? || snapshot[:received_at] > prev_at ? :report : :rule_enabled
    end

    new_snapshot = prev_at.nil? || change[:prev_snapshot_id] != change.config_snapshot_id
    new_version = prev_at.nil? || change[:prev_version_id] != change.cis_rule_version_id
    if new_snapshot && (!new_version || snapshot[:received_at] >= version.created_at) then :report
    elsif new_version then :rule_edited
    else :reevaluated
    end
  end

  # { snapshot id => { received_at:, facts:, previous_facts: (nil for the host's first snapshot) } }.
  def snapshot_facts(ids)
    return {} if ids.empty?

    order = ConfigSnapshot.where(host_id: @host_id).order(:received_at, :id).pluck(:id)
    previous = ids.to_h { |id| [ id, (i = order.index(id)) && i.positive? ? order[i - 1] : nil ] }
    loaded = ConfigSnapshot.where(id: ids + previous.values.compact).pluck(:id, :received_at, :facts).to_h { |id, at, facts| [ id, [ at, facts ] ] }
    ids.to_h do |id|
      received_at, facts = loaded.fetch(id)
      [ id, { received_at:, facts:, previous_facts: previous[id] && loaded.dig(previous[id], 1) } ]
    end
  end

  # Audit entries for rule edits, enables, and disables, with the operator's name: [[rule_id, cause, entry, name]].
  def audit_entries(rule_ids)
    entries = AuditEntry.where(target_type: "CisRule", target_id: rule_ids, action: AUDITED.keys).order(:occurred_at, :id).to_a
    names = Operator.where(id: entries.select { |e| e.actor_type == "operator" }.map(&:actor_id)).index_by(&:id)
    entries.map { |e| [ e.target_id, AUDITED.fetch(e.action), e, e.actor_type == "operator" ? names[e.actor_id]&.display_name : nil ] }
  end

  # Who made the rule change behind a change of result, when an operator did: for an edit, the entry that created
  # that version; for an enable or disable, the entry nearest in time (evaluation runs just after it commits; audit
  # times are the database's clock, result changes the application's).
  def actor(audits, change, cause, version)
    return nil unless cause.in?(%i[rule_edited rule_enabled rule_disabled])

    candidates = audits.select { |rule_id, kind, _, _| rule_id == change.cis_rule_id && kind == cause }
    return candidates.find { |_, _, entry, _| entry.changeset.dig("version", 1) == version&.version }&.last if cause == :rule_edited

    candidates.min_by { |_, _, entry, _| (entry.occurred_at - change.occurred_at).abs }&.last
  end
end
