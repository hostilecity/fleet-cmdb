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
    DECISION_SLICE = 100

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
      due = due_by_host(now)
      ended = 0
      slices(due).each do |hosts, advisories|
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

    # { host id => [advisory ids] } of the active decisions past their last day or with worse evidence: the active rows
    # in id order (a partial index keeps the scan off the ended ones), a batch at a time, keeping only the due rows'
    # host and advisory, so memory grows with what is due and each slice reads its own hosts' lists.
    def due_by_host(now)
      today = now.to_date
      due = Hash.new { |h, k| h[k] = [] }
      signals = {}
      FindingDecision.active.in_batches(of: BATCH) do |batch|
        rows = batch.pluck(:host_id, :advisory_id, :expires_on, :evidence)
        missing = rows.map { |row| row[1] }.uniq - signals.keys
        signals.merge!(FindingDecisions.signals(missing)) if missing.any?
        rows.each do |host_id, advisory_id, expires_on, evidence|
          due[host_id] << advisory_id if expires_on < today || FindingDecisions.worsened(evidence, signals.fetch(advisory_id)).any?
        end
      end
      due.default_proc = nil
      due
    end

    # [[host ids, advisory ids]] in host id order: at most HOST_SLICE hosts and DECISION_SLICE due decisions a slice (a
    # host with more is split by advisory), so a mass expiry or suspension holds each slice's host locks briefly.
    def slices(due)
      units = due.keys.sort.flat_map { |host| due.fetch(host).each_slice(DECISION_SLICE).map { |advisories| [ host, advisories ] } }
      list = []
      count = 0
      units.each do |host, advisories|
        last = list.last
        if last.nil? || last[0].size >= HOST_SLICE || count + advisories.size > DECISION_SLICE
          list << [ [], [] ]
          count = 0
        end
        list.last[0] << host unless list.last[0].last == host
        list.last[1].concat(advisories)
        count += advisories.size
      end
      list.map { |hosts, advisories| [ hosts, advisories.uniq ] }
    end

    # Ends a decision past its last day as expired, now, and re-triages its findings: when an operator opens it to change
    # or end it before the hourly job does, so it is never revived.
    def expire!(decision, now: Time.current)
      finish!(decision, "expired", Audit::Actions::VULNERABILITY_DECISION_EXPIRED, now:)
      VulnerabilityMatcher.retriage!([ decision.host_id ], advisory_ids: [ decision.advisory_id ])
      true
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

    private_class_method :scope, :finish!, :due_by_host, :slices
  end
end
