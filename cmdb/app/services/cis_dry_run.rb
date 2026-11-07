# Dry run of an unsaved CIS-aligned rule definition (P2-S14, FR-2.2, AC-2.2): which hosts would change result if
# the definition were saved, for the rule edit and add-rule previews (P2-D06). It writes nothing (no result, change, version,
# audit entry, or job) and contacts no agent.
#
#   result = CisDryRun.call(rule)   # rule: a Hash as a rule file holds one rule, or a CisRules::Definition
#   result.ok?                      # false: result.errors lists every problem, each with a JSON Pointer into the rule
#   result.preview.changes          # the hosts whose result would change
#   result.preview.counts           # what the preview page counts
#
# - Validated with the same checks as an import (CisRules::RuleFile.parse_rule). A rule file's `enabled` is
#   honoured as an import honours it: stated, it is the flag after saving; left out, an existing rule keeps
#   its flag and a new one is enabled.
# - Evaluated as saving would evaluate it (CisRule.define! then CisEvaluation): on every host in the fleet (not
#   retired), from its latest config snapshot and the os of its inventory, with CisEvaluation.outcome, so the
#   evaluator, applicability, not-readable, and not-evaluated rules are the same. A host's current result is its
#   stored CisResult for the rule; a new rule (its key not defined yet) has none on any host.
# - A host that would drop out, going from a real result (pass, fail, or not_readable) to not_applicable, is
#   listed (kind :to_not_applicable), so the operator sees which hosts the rule would stop checking. Any other
#   host the rule would not apply to (already not applicable, or with no result yet, as on a new rule), and a
#   host with no config report, is counted and not listed, even when its stored result would change; those are
#   counted again in unlisted_changes, so listed plus unlisted changes are exactly what saving records. Saving a
#   definition identical to the current version with the same flag writes nothing, so the preview then has no
#   changes ("no change").
# - Reads only: six queries whatever the size of the fleet (the rule and its current version, the hosts, their
#   latest snapshots reading just the rule's fact, their inventories, the rule's results), none locking anything, so an agent
#   report is never waited for or blocked. Outside a transaction they run in one REPEATABLE READ, READ ONLY
#   transaction, so they see one consistent state and cannot write.
# - Advisory: saving evaluates the rule as it is then, so if the rule or a snapshot changes in between, the
#   saved results may differ from the preview.
module CisDryRun
  Result = Data.define(:errors, :preview) do
    def ok? = errors.empty?
  end

  # key, rule_id, and current_version are nil for a new rule; next_version is nil when saving makes no new version.
  # currently_enabled and enabled are the flag now (nil for a new rule) and after saving; saves_nothing? when saving
  # would change nothing at all.
  Preview = Data.define(:key, :rule_id, :current_version, :next_version, :currently_enabled, :enabled, :changes, :counts) do
    def new_rule? = rule_id.nil?

    def saves_nothing? = !new_rule? && next_version.nil? && enabled == currently_enabled
  end

  # One host whose result would change. from (and current_observed) are nil when the host has no stored result;
  # observed and reason are those under the definition.
  Change = Data.define(:host_id, :host_name, :hostname, :from, :to, :observed, :reason, :current_observed) do
    def kind
      if from == "pass" && to == "fail" then :pass_to_fail
      elsif from == "fail" && to == "pass" then :fail_to_pass
      elsif to == "not_applicable" then :to_not_applicable
      else :other
      end
    end
  end

  # The real results a host can drop out from: a listed change when the rule would no longer apply.
  REAL_RESULTS = %w[pass fail not_readable].freeze

  # hosts             every host in the fleet; each is counted once in changed, unchanged, not_applicable, or no_report
  # changed           listed changes (pass_to_fail + fail_to_pass + to_not_applicable + other_changes)
  # not_applicable    hosts the rule would not apply to, other than those listed as to_not_applicable
  # unlisted_changes  hosts counted in not_applicable or no_report whose stored result would also change
  Counts = Data.define(:hosts, :changed, :pass_to_fail, :fail_to_pass, :to_not_applicable, :other_changes, :unchanged, :not_applicable,
                       :no_report, :unlisted_changes)

  module_function

  def call(rule, manifest: ConfigManifest.current)
    rule = rule.to_h.transform_keys(&:to_s) if rule.is_a?(CisRules::Definition)
    file = CisRules::RuleFile.parse_rule(rule, manifest:)
    return Result.new(errors: file.problems, preview: nil) unless file.valid?

    parsed = file.rules.sole
    Result.new(errors: [], preview: read_only { preview(parsed.definition, parsed.enabled, manifest) })
  end

  def preview(definition, stated_enabled, manifest)
    stored = CisRule.includes(:current_version).find_by(key: definition.key)
    current = stored&.current_version
    enabled = stated_enabled.nil? ? (stored ? stored.enabled : true) : stated_enabled
    next_version = if current.nil? then 1
    elsif current.content_hash != definition.content_hash then current.version + 1
    end
    flag_unchanged = stored.nil? || stored.enabled == enabled
    saves = next_version || !flag_unchanged # whether saving re-evaluates the rule (CisRule.define!, enable!, disable!)

    hosts = Host.in_fleet.order(:id).pluck(:id, :name, :hostname)
    ids = hosts.map(&:first)
    facts = latest_facts(ids, definition.fact)
    os = HostInventory.where(host_id: ids).pluck(:host_id, CisEvaluation::OS).to_h
    results = stored ? CisResult.where(cis_rule_id: stored.id, host_id: ids).pluck(:host_id, :result, :observed).to_h { |id, *rest| [ id, rest ] } : {}

    tally = Hash.new(0)
    changes = []
    hosts.each do |host_id, name, hostname|
      from, current_observed = results[host_id]
      outcome = CisEvaluation.outcome(definition, enabled:, facts: facts[host_id], os: os[host_id], manifest:)
      changing = saves && CisEvaluation.change?(from, outcome.result)
      bucket = if !facts.key?(host_id) then :no_report
      elsif outcome.result == "not_applicable" && !(changing && REAL_RESULTS.include?(from)) then :not_applicable
      end
      if bucket
        tally[bucket] += 1
        tally[:unlisted_changes] += 1 if changing
      elsif changing
        change = Change.new(host_id:, host_name: name, hostname:, from:, to: outcome.result, observed: outcome.observed, reason: outcome.reason, current_observed:)
        changes << change
        tally[change.kind] += 1
      else
        tally[:unchanged] += 1
      end
    end

    counts = Counts.new(hosts: hosts.size, changed: changes.size, pass_to_fail: tally[:pass_to_fail], fail_to_pass: tally[:fail_to_pass], to_not_applicable: tally[:to_not_applicable],
                        other_changes: tally[:other],
                        unchanged: tally[:unchanged], not_applicable: tally[:not_applicable], no_report: tally[:no_report],
                        unlisted_changes: tally[:unlisted_changes])
    Preview.new(key: definition.key, rule_id: stored&.id, current_version: current&.version, next_version:, currently_enabled: stored&.enabled, enabled:,
                changes: changes.sort_by { |change| [ change.host_name.downcase, change.host_id ] }, counts:)
  end

  # { host_id => { fact => reported } } from each host's latest config snapshot, reading only the one fact; a
  # host with no snapshot is absent, and a snapshot without the fact gives {} (the fact is missing).
  def latest_facts(host_ids, fact)
    reported = ConfigSnapshot.sanitize_sql_array([ "config_snapshots.facts -> ?", fact ])
    ConfigSnapshot.where(host_id: host_ids).order(:host_id, CisEvaluation::LATEST_SNAPSHOT)
                  .pluck(Arel.sql("DISTINCT ON (config_snapshots.host_id) config_snapshots.host_id"), Arel.sql(reported))
                  .to_h { |host_id, value| [ host_id, value.nil? ? {} : { fact => value } ] }
  end

  # Inside a caller's transaction the reads join it; otherwise they share one read-only snapshot of the database.
  def read_only(&)
    connection = ActiveRecord::Base.connection
    return yield if connection.transaction_open?

    ActiveRecord::Base.transaction(isolation: :repeatable_read) do
      connection.execute("SET TRANSACTION READ ONLY")
      yield
    end
  end

  private_class_method :preview, :latest_facts, :read_only
end
