module FindingDecisions
  # How decisions end without an operator (VT-OVERRIDES #261, VT-S06), audited as the system. A decision never
  # silently outlives its expiry or its evidence:
  #
  # - review!(host_ids): for the hosts' active decisions, ends those past their last day (decision_expired) and
  #   suspends those whose evidence got worse than recorded (decision_suspended, with what changed). Called under the
  #   hosts' row locks before their transitions read the controls (VulnerabilityMatcher), so a suspended control
  #   stops applying in the same pass that sees the new evidence: a KEV listing's triage run suspends at once.
  # - settle!(host_ids): after the transitions wrote the findings, ends the active decisions whose findings resolved
  #   (resolved) or got a fix (fixed: K1, K2, F1, F2), as decision_ended by the system.
  # - sweep!: FindingDecisionExpiryJob, hourly. Finds every active decision past its last day or with worse evidence
  #   (a batch of decisions and their advisories' signals at a time), and for each slice of their hosts reviews them
  #   under the hosts' locks and re-triages the advisories' findings in the same transaction. It also catches what no
  #   re-triage reaches, such as an EPSS band turning high on an advisory already in rule N1, whose bucket does not move.
  module Lifecycle
    BATCH = 5_000
    HOST_SLICE = 100

    module_function

    # Returns the host ids that still have an active decision (for settle!). advisory_ids: only those advisories'.
    def review!(host_ids, advisory_ids: nil, now: Time.current)
      decisions = scope(host_ids, advisory_ids).preload(:advisory, :host).to_a
      return [] if decisions.empty?

      signals = FindingDecisions.signals(decisions.map(&:advisory_id))
      today = now.to_date
      decisions.reject do |decision|
        if decision.lapsed?(today)
          finish!(decision, "expired", Audit::Actions::VULNERABILITY_DECISION_EXPIRED, now:)
        elsif (changes = FindingDecisions.worsened(decision.evidence, signals.fetch(decision.advisory_id))).any?
          finish!(decision, "suspended", Audit::Actions::VULNERABILITY_DECISION_SUSPENDED, now:, evidence: changes)
        end
      end.map(&:host_id).uniq
    end

    # Ends the hosts' active decisions whose findings all resolved, or one of which got a fix.
    def settle!(host_ids, advisory_ids: nil, now: Time.current)
      return if host_ids.empty?

      decisions = scope(host_ids, advisory_ids).preload(:advisory, :host).to_a
      return if decisions.empty?

      rules = VulnerabilityFinding.active.where(host_id: decisions.map(&:host_id).uniq, advisory_id: decisions.map(&:advisory_id).uniq)
                                  .pluck(:host_id, :advisory_id, :bucket_rule).group_by { |host_id, advisory_id, _| [ host_id, advisory_id ] }
      decisions.each do |decision|
        found = rules.fetch([ decision.host_id, decision.advisory_id ], []).map { |*, rule| VulnerabilityTriage.rule_for(rule) }
        why = if found.empty? then "resolved"
        elsif found.intersect?(FindingDecisions::FIX_RULES) then "fixed"
        end
        finish!(decision, why, Audit::Actions::VULNERABILITY_DECISION_ENDED, now:) if why
      end
    end

    # The hourly pass. Returns how many decisions it ended.
    def sweep!(now: Time.current)
      today = now.to_date
      due = []
      signals = {}
      FindingDecision.active.in_batches(of: BATCH) do |batch|
        rows = batch.pluck(:id, :host_id, :advisory_id, :expires_on, :evidence)
        missing = rows.map { |row| row[2] }.uniq - signals.keys
        signals.merge!(FindingDecisions.signals(missing)) if missing.any?
        due.concat(rows.select { |_, _, advisory_id, expires_on, evidence| expires_on < today || FindingDecisions.worsened(evidence, signals.fetch(advisory_id)).any? })
      end
      ended = 0
      due.group_by { |row| row[1] }.keys.sort.each_slice(HOST_SLICE) do |hosts|
        advisories = due.select { |row| hosts.include?(row[1]) }.map { |row| row[2] }.uniq
        FindingDecision.transaction do
          Host.lock.where(id: hosts).order(:id).pluck(:id)
          before = scope(hosts, advisories).count
          review!(hosts, advisory_ids: advisories, now:)
          ended += before - scope(hosts, advisories).count
          VulnerabilityMatcher.retriage!(hosts, advisory_ids: advisories)
        end
      end
      ended
    end

    def scope(host_ids, advisory_ids)
      scope = FindingDecision.active.where(host_id: host_ids)
      advisory_ids ? scope.where(advisory_id: advisory_ids) : scope
    end

    def finish!(decision, why, action, now:, evidence: nil)
      decision.update!(ended_at: now, ended_why: why, ended_evidence: evidence)
      changes = FindingDecisions.identity(decision).merge("ended_why" => why, "until" => decision.expires_on.iso8601)
      changes["changed_evidence"] = FindingDecisions.changes_words(evidence) if evidence
      Audit.record(actor: Audit::SYSTEM, action:, target: decision.host, changes: changes.compact, request_id: nil)
      true
    end

    private_class_method :scope, :finish!
  end
end
