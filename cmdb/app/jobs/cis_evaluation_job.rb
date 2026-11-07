# Runs CIS rule evaluation in the background (P2-S06, FR-2.2): agents are never involved.
#
# - host_ids alone: those hosts, every rule (after a new config snapshot, ConfigRecorder; after the host's
#   operating system changes, InventoryRecorder, since a rule's applies_to depends on it).
# - rule_ids alone: every host in the fleet, those rules (after a rule is created, edited, enabled, or disabled).
#
# Enqueued once the transaction commits, so the job sees what it was enqueued for. Retries follow
# ApplicationJob, and evaluation is idempotent, so a retried or duplicated run is safe.
class CisEvaluationJob < ApplicationJob
  queue_as :default

  def self.after_snapshot(host_id) = ActiveRecord.after_all_transactions_commit { perform_later(host_ids: [ host_id ]) }

  def self.after_rule_change(rule_id) = ActiveRecord.after_all_transactions_commit { perform_later(rule_ids: [ rule_id ]) }

  def perform(host_ids: nil, rule_ids: nil)
    return CisEvaluation.evaluate!(host_ids) if host_ids

    CisEvaluation.evaluate!(Host.in_fleet.pluck(:id), rule_ids:)
  end
end
