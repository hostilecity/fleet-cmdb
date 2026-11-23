# Operator decisions on a host's finding (VT-OVERRIDES #261, VT-S06, FR-2.6; ADR 0032; epic decisions 12, 14, 15): a
# compensating control in place (rule O1: the finding moves to Low risk, scored as "by a control") or a risk accepted
# (no bucket, points, or tier change; it only leaves "decisions due"), with a reason, an expiry date, who recorded it,
# and the evidence it was recorded on. One row per host and advisory decision, covering every binary package the
# advisory matches on the host.
#
# - One active decision (ended_at NULL) per host and advisory: the partial unique index.
# - A decision ends once, for one reason: an operator ended it, it expired, a fix appeared, every finding it covers
#   resolved, or the evidence got worse than recorded (suspended, with what changed in ended_evidence). Ended is
#   final, and a decision is never deleted (finding_decisions_guard): it stays visible with why, and the audit log
#   records every change.
# - expires_on is the last day it applies (UTC); FindingDecisionExpiryJob ends it within the hour after that day.
# - The control source (VulnerabilityTriage::HostFacts.control_source) reads the active controls of a batch's hosts by
#   the partial unique index; the expiry job finds due decisions by expires_on and the decisions of an advisory by
#   advisory_id, both partial on the active rows. A new table, so no lock on a busy one.
class CreateFindingDecisions < ActiveRecord::Migration[8.1]
  KINDS = %w[control accepted].freeze
  ENDINGS = %w[operator expired fixed suspended resolved].freeze

  def change
    create_table :finding_decisions do |t|
      t.bigint :host_id, null: false
      t.bigint :advisory_id, null: false
      t.string :kind, limit: 16, null: false
      t.text :reason, null: false
      t.date :expires_on, null: false
      t.bigint :created_by_id, null: false
      t.boolean :confirmed, null: false, default: false
      t.jsonb :evidence, null: false
      t.string :request_id, limit: 128
      t.datetime :ended_at
      t.bigint :ended_by_id
      t.string :ended_why, limit: 16
      t.jsonb :ended_evidence
      t.timestamps

      t.index %i[host_id advisory_id], unique: true, where: "ended_at IS NULL", name: "index_finding_decisions_active"
      t.index %i[host_id advisory_id id], name: "index_finding_decisions_history"
      t.index :expires_on, where: "ended_at IS NULL", name: "index_finding_decisions_active_expiry"
      t.index :advisory_id, where: "ended_at IS NULL", name: "index_finding_decisions_active_advisory"

      t.check_constraint "kind IN (#{KINDS.map { |k| "'#{k}'" }.join(', ')})", name: "finding_decisions_kind_valid"
      t.check_constraint "char_length(reason) BETWEEN 10 AND 1000", name: "finding_decisions_reason_length"
      t.check_constraint "jsonb_typeof(evidence) = 'object' AND octet_length(evidence::text) <= 8192", name: "finding_decisions_evidence_object"
      t.check_constraint "ended_evidence IS NULL OR (jsonb_typeof(ended_evidence) = 'object' AND octet_length(ended_evidence::text) <= 8192)",
                         name: "finding_decisions_ended_evidence_object"
      t.check_constraint "(ended_at IS NULL) = (ended_why IS NULL)", name: "finding_decisions_ended_why"
      t.check_constraint "ended_why IS NULL OR ended_why IN (#{ENDINGS.map { |e| "'#{e}'" }.join(', ')})", name: "finding_decisions_ended_why_valid"
      # Only an operator's end names an operator; the system's never does.
      t.check_constraint "(ended_by_id IS NOT NULL) = (ended_why IS NOT DISTINCT FROM 'operator')", name: "finding_decisions_ended_by"
      # A control is confirmed for its host (epic decision 15); an acceptance needs no confirmation.
      t.check_constraint "kind <> 'control' OR confirmed", name: "finding_decisions_control_confirmed"
    end
    add_foreign_key :finding_decisions, :hosts
    add_foreign_key :finding_decisions, :advisories
    add_foreign_key :finding_decisions, :operators, column: :created_by_id
    add_foreign_key :finding_decisions, :operators, column: :ended_by_id

    create_function :finding_decisions_guard
    create_trigger :finding_decisions_guard, on: :finding_decisions
    create_trigger :finding_decisions_no_truncate, on: :finding_decisions
  end
end
