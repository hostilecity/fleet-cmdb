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

  PENDING_RULES = :cis_evaluation_job_pending_rule_ids

  # Every rule changed in one transaction (a rules file import changes many) is evaluated by one job once it commits, so
  # one import is one fleet-wide run and one live refresh (P2-D05), not one per rule. The ids wait in this thread's
  # execution state until the outermost transaction commits, and are dropped if it rolls back.
  def self.after_rule_change(rule_id)
    pending = (ActiveSupport::IsolatedExecutionState[PENDING_RULES] ||= [])
    pending << rule_id
    return if pending.size > 1 # already scheduled for this transaction

    ActiveRecord::Base.current_transaction.after_rollback { ActiveSupport::IsolatedExecutionState.delete(PENDING_RULES) }
    ActiveRecord.after_all_transactions_commit do
      ids = ActiveSupport::IsolatedExecutionState.delete(PENDING_RULES)
      perform_later(rule_ids: ids.uniq) if ids
    end
  end

  # One run, then one live refresh of the fleet pages when what they show changed on any host (P2-D05). Each host is
  # evaluated in its own transaction, all committed by the time the run returns, so the refresh follows the commits.
  def perform(host_ids: nil, rule_ids: nil)
    outcome = host_ids ? CisEvaluation.evaluate!(host_ids) : CisEvaluation.evaluate!(Host.in_fleet.pluck(:id), rule_ids:)
    FleetBroadcast.hosts_changed(outcome.changed_host_ids)
    outcome
  end
end
