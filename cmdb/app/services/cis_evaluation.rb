# Evaluates CIS-aligned rules on hosts and stores the results (P2-S06, FR-2.2, DEC-12). Agents are never
# involved: a host is evaluated from its latest config snapshot and the os of its inventory, by the pure
# CisRules::Evaluator. Run by CisEvaluationJob after a new config snapshot or a change of operating system (that
# host, every rule), and after a rule is created, edited, enabled, or disabled (every host, that rule).
#
# - One CisResult per host and rule, always naming the rule version and the snapshot used. A disabled rule is
#   not_evaluated, as is every rule on a host that has sent no config report.
# - A CisResultChange is written only when the result changes (pass to fail, fail to not_readable, ...), never
#   for the same result with another observed value, so running evaluation again writes no history.
# - Each host is evaluated in its own short transaction holding its row lock (FOR UPDATE, as AgentHostLock
#   takes for every agent write), so a config report in progress is waited for, never half seen, and two runs
#   for one host are serialised. Idempotent: a retried or duplicated run changes nothing more.
# - The rules, the snapshot, and the time are all read once the host is locked, bypassing the query cache, so
#   a run that waited for the lock never writes an older rule's result over a newer one or dates a change
#   before the one it follows (review of #110).
module CisEvaluation
  Outcome = Data.define(:hosts, :results, :changes)

  DISABLED = "The rule is disabled."
  NO_REPORT = "The host has not sent a config report."
  LATEST_SNAPSHOT = { received_at: :desc, id: :desc }.freeze # a host's latest config snapshot comes first
  OS = Arel.sql("stable -> 'os'") # the os-release id and version_id applies_to is matched against, from HostInventory
  COLUMNS = %i[host_id cis_rule_id cis_rule_version_id config_snapshot_id result observed reason evaluated_at changed_at].freeze

  module_function

  # host_ids: the hosts to evaluate (retired hosts are skipped); rule_ids: the rules, or nil for every rule.
  # now: the evaluation time, by default the time each host's lock is taken.
  def evaluate!(host_ids, rule_ids: nil, now: nil)
    outcome = Hash.new(0)
    return Outcome.new(hosts: 0, results: 0, changes: 0) if rule_ids&.empty?

    Host.in_fleet.where(id: host_ids).order(:id).pluck(:id).each do |host_id|
      CisResult.transaction do
        CisResult.uncached do
          next unless Host.lock.in_fleet.find_by(id: host_id) # FOR UPDATE: waits for a config report in progress

          rules = (rule_ids ? CisRule.where(id: rule_ids) : CisRule.all).includes(:current_version).order(:id).to_a
          next if rules.empty?

          changes = evaluate_host(host_id, rules, now || Time.current)
          outcome[:hosts] += 1
          outcome[:results] += rules.size
          outcome[:changes] += changes
        end
      end
    end
    Outcome.new(hosts: outcome[:hosts], results: outcome[:results], changes: outcome[:changes])
  end

  # Returns how many results changed.
  def evaluate_host(host_id, rules, now)
    snapshot = ConfigSnapshot.where(host_id:).order(LATEST_SNAPSHOT).first
    os = HostInventory.where(host_id:).pick(OS)
    existing = CisResult.where(host_id:, cis_rule_id: rules.map(&:id)).index_by(&:cis_rule_id)
    rows = []
    changes = []
    rules.each do |rule|
      outcome = result_for(rule, snapshot, os)
      before = existing[rule.id]
      changed = change?(before&.result, outcome.result)
      version_id = outcome.result == "not_evaluated" ? nil : rule.current_version_id
      snapshot_id = outcome.result == "not_evaluated" ? nil : snapshot&.id
      rows << { host_id:, cis_rule_id: rule.id, cis_rule_version_id: version_id, config_snapshot_id: snapshot_id, result: outcome.result,
                observed: outcome.observed, reason: outcome.reason, evaluated_at: now, changed_at: changed ? now : before.changed_at }
      next unless changed

      changes << { host_id:, cis_rule_id: rule.id, cis_rule_version_id: version_id, config_snapshot_id: snapshot_id, from_result: before&.result,
                   to_result: outcome.result, observed: outcome.observed, reason: outcome.reason, occurred_at: now }
    end
    CisResult.upsert_all(rows, unique_by: %i[host_id cis_rule_id], update_only: COLUMNS - %i[host_id cis_rule_id], record_timestamps: false)
    CisResultChange.insert_all(changes, record_timestamps: false) if changes.any?
    changes.size
  end

  def result_for(rule, snapshot, os) = outcome(rule.current_version, enabled: rule.enabled, facts: snapshot&.facts, os:)

  # The result a rule definition has on a host, as stored: not_evaluated when the rule is disabled or the host
  # has sent no config report (facts nil), otherwise the evaluator's. Shared with the dry run (CisDryRun, P2-S14).
  def outcome(definition, enabled:, facts:, os:, manifest: ConfigManifest.current)
    return CisRules::Evaluator::Outcome.new(result: "not_evaluated", observed: nil, reason: DISABLED) unless enabled
    return CisRules::Evaluator::Outcome.new(result: "not_evaluated", observed: nil, reason: NO_REPORT) unless facts

    CisRules::Evaluator.call(definition, facts, os, manifest:)
  end

  # Whether going from the stored result (nil when there is none) to this one is a change, which is recorded.
  def change?(before, after) = before != after

  private_class_method :evaluate_host, :result_for
end
