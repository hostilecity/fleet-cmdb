# Evaluates CIS-aligned rules on hosts and stores the results (P2-S06, FR-2.2, DEC-12). Agents are never
# involved: a host is evaluated from its latest config snapshot and the os of its inventory, by the pure
# CisRules::Evaluator. Run by CisEvaluationJob after a new config snapshot or a change of operating system (that
# host, every rule), and after a rule is created, edited, enabled, or disabled (every host, that rule).
#
# - One CisResult per host and rule, always naming the rule version and the snapshot used. A disabled rule is
#   not_evaluated, as is every rule on a host that has sent no config report.
# - A CisResultChange is written only when the result changes (pass to fail, fail to not_readable, ...), never
#   for the same result with another observed value, so running evaluation again writes no history.
# - Hosts are evaluated in chunks, each in its own short transaction holding the chunk's host rows (FOR UPDATE in id
#   order, as AgentHostLock takes one for every agent write), so a config report in progress is waited for, never
#   half seen, and two runs for one host are serialised. Locking in id order means two runs never deadlock; a chunk
#   holds its rows for one set-based read and write, not for the whole run (#197). A chunk is sized by its work, at
#   most EVALUATIONS_PER_CHUNK host-and-rule evaluations and LOCK_CHUNK hosts, and then by time: each next chunk is
#   scaled so it holds its locks for about LOCK_TARGET, so a heartbeat or report waits about that long at most
#   (review of #204).
#   Idempotent: a retried or duplicated run changes nothing more.
# - The rules, the snapshots, and the time are all read once the chunk is locked, bypassing the query cache, so
#   a run that waited for the lock never writes an older rule's result over a newer one or dates a change
#   before the one it follows (review of #110).
# - Only what a result needs is read (#197): the facts the rules name, and those only on hosts where at least one
#   of the rules is enabled and applies. A host none of them applies to is not_applicable (or not_evaluated, or
#   not_readable) from its operating system and whether it has a snapshot, without reading its facts.
module CisEvaluation
  # changed_host_ids: the hosts whose shown compliance changed (a result, or the rule version a failure is counted
  # under, since its severity comes from that version), for the live refresh (P2-D05).
  Outcome = Data.define(:hosts, :results, :changes, :changed_host_ids)

  DISABLED = "The rule is disabled."
  NO_REPORT = "The host has not sent a config report."
  LATEST_SNAPSHOT = { received_at: :desc, id: :desc }.freeze # a host's latest config snapshot comes first
  OS = Arel.sql("stable -> 'os'") # the os-release id and version_id applies_to is matched against, from HostInventory
  COLUMNS = %i[host_id cis_rule_id cis_rule_version_id config_snapshot_id result observed reason evaluated_at changed_at].freeze

  module_function

  # The most hosts locked at once: a chunk is read, evaluated, and written while its rows are held.
  LOCK_CHUNK = 100
  # The most host-and-rule evaluations in one chunk: 100 hosts for one rule, 14 for the 71 starter rules.
  EVALUATIONS_PER_CHUNK = 1_000
  # How long a chunk should hold its host rows, in seconds; the next chunk is sized from the last one's time.
  LOCK_TARGET = 0.2

  # host_ids: the hosts to evaluate (retired hosts are skipped); rule_ids: the rules, or nil for every rule.
  # now: the evaluation time, by default the time each chunk's locks are taken.
  def evaluate!(host_ids, rule_ids: nil, now: nil)
    outcome = Hash.new(0)
    changed_host_ids = []
    return Outcome.new(hosts: 0, results: 0, changes: 0, changed_host_ids:) if rule_ids&.empty?

    ids = Host.in_fleet.where(id: host_ids).order(:id).pluck(:id)
    cap = chunk_cap(rule_ids ? rule_ids.size : CisRule.count) # read unlocked, only to size the chunks
    size = cap
    until ids.empty?
      chunk = ids.shift(size)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      CisResult.transaction do
        CisResult.uncached do
          locked = Host.lock.in_fleet.where(id: chunk).order(:id).pluck(:id) # FOR UPDATE: waits for config reports in progress
          next if locked.empty?

          rules = (rule_ids ? CisRule.where(id: rule_ids) : CisRule.all).includes(:current_version).order(:id).to_a
          next if rules.empty?

          changes, shown_changed = evaluate_hosts(locked, rules, now || Time.current)
          outcome[:hosts] += locked.size
          outcome[:results] += locked.size * rules.size
          outcome[:changes] += changes
          changed_host_ids.concat(shown_changed)
        end
      end
      size = next_chunk_size(size, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, cap)
    end
    Outcome.new(hosts: outcome[:hosts], results: outcome[:results], changes: outcome[:changes], changed_host_ids:)
  end

  # The most hosts in a chunk for this many rules: EVALUATIONS_PER_CHUNK evaluations, at most LOCK_CHUNK hosts.
  def chunk_cap(rule_count) = (EVALUATIONS_PER_CHUNK / [ rule_count, 1 ].max).clamp(1, LOCK_CHUNK)

  # The next chunk's size, scaled from how long the last one held its locks so it takes about LOCK_TARGET.
  def next_chunk_size(size, seconds, cap) = (size * LOCK_TARGET / [ seconds, 0.001 ].max).floor.clamp(1, cap)

  # Evaluates the locked hosts with one read of each kind and one write. Returns how many results changed, and the
  # hosts whose shown compliance changed: a result, or the version a failure is counted under.
  def evaluate_hosts(host_ids, rules, now)
    os = HostInventory.where(host_id: host_ids).pluck(:host_id, OS).to_h
    snapshots = latest_snapshot_ids(host_ids)
    facts = latest_facts(host_ids.select { |id| snapshots.key?(id) && needs_facts?(rules, os[id]) }, snapshots, rules)
    existing = CisResult.where(host_id: host_ids, cis_rule_id: rules.map(&:id)).index_by { |result| [ result.host_id, result.cis_rule_id ] }
    rows = []
    changes = []
    shown_changed = []
    host_ids.each do |host_id|
      snapshot_id = snapshots[host_id]
      # A host with a snapshot whose facts were not read needs none of them: every rule is decided before a fact is.
      host_facts = facts.fetch(host_id) { snapshot_id && {} }
      shown = false
      rules.each do |rule|
        outcome = outcome(rule.current_version, enabled: rule.enabled, facts: host_facts, os: os[host_id])
        before = existing[[ host_id, rule.id ]]
        changed = change?(before&.result, outcome.result)
        evaluated = outcome.result != "not_evaluated"
        version_id = evaluated ? rule.current_version_id : nil
        used_snapshot = evaluated ? snapshot_id : nil
        rows << { host_id:, cis_rule_id: rule.id, cis_rule_version_id: version_id, config_snapshot_id: used_snapshot, result: outcome.result,
                  observed: outcome.observed, reason: outcome.reason, evaluated_at: now, changed_at: changed ? now : before.changed_at }
        shown ||= changed || (outcome.result == "fail" && before.cis_rule_version_id != version_id)
        next unless changed

        changes << { host_id:, cis_rule_id: rule.id, cis_rule_version_id: version_id, config_snapshot_id: used_snapshot, from_result: before&.result,
                     to_result: outcome.result, observed: outcome.observed, reason: outcome.reason, occurred_at: now }
      end
      shown_changed << host_id if shown
    end
    CisResult.upsert_all(rows, unique_by: %i[host_id cis_rule_id], update_only: COLUMNS - %i[host_id cis_rule_id], record_timestamps: false)
    CisResultChange.insert_all!(changes, record_timestamps: false) if changes.any?
    [ changes.size, shown_changed ]
  end

  # Whether any of the rules needs the host's facts: it is enabled and applies to the host's operating system.
  def needs_facts?(rules, os)
    CisRules::Evaluator.os_known?(os) && rules.any? { |rule| rule.enabled && CisRules::Evaluator.applies?(rule.current_version.applies_to, os) }
  end

  # { host_id => id of its latest config snapshot }, for hosts that have one.
  def latest_snapshot_ids(host_ids)
    Partitions.with_set_aside(ConfigSnapshot).where(host_id: host_ids).order(:host_id, LATEST_SNAPSHOT)
                  .pluck(Arel.sql("DISTINCT ON (config_snapshots.host_id) config_snapshots.host_id"), :id).to_h
  end

  # { host_id => { fact => reported } } from the given snapshots, reading only the facts the rules name.
  def latest_facts(host_ids, snapshots, rules)
    return {} if host_ids.empty?

    names = rules.map { |rule| rule.current_version.fact }.uniq
    named = ConfigSnapshot.sanitize_sql_array([ "(SELECT COALESCE(jsonb_object_agg(fact.key, fact.value), '{}') " \
                                                "FROM jsonb_each(config_snapshots.facts) fact WHERE fact.key IN (?))", names ])
    Partitions.with_set_aside(ConfigSnapshot).where(id: host_ids.map { |id| snapshots[id] }).pluck(:host_id, Arel.sql(named)).to_h
  end

  # The result a rule definition has on a host, as stored: not_evaluated when the rule is disabled or the host
  # has sent no config report (facts nil), otherwise the evaluator's. Shared with the dry run (CisDryRun, P2-S14).
  def outcome(definition, enabled:, facts:, os:, manifest: ConfigManifest.current)
    return CisRules::Evaluator::Outcome.new(result: "not_evaluated", observed: nil, reason: DISABLED) unless enabled
    return CisRules::Evaluator::Outcome.new(result: "not_evaluated", observed: nil, reason: NO_REPORT) unless facts

    CisRules::Evaluator.call(definition, facts, os, manifest:)
  end

  # Whether going from the stored result (nil when there is none) to this one is a change, which is recorded.
  def change?(before, after) = before != after

  private_class_method :chunk_cap, :next_chunk_size, :evaluate_hosts, :needs_facts?, :latest_snapshot_ids, :latest_facts
end
