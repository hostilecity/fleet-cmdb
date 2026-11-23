# Operator decisions on findings (VT-OVERRIDES #261, VT-S06, FR-2.6, FR-S.3; ADR 0032; epic decisions 12, 14, 15):
# record a compensating control (rule O1) or accept a risk, per host and advisory, with a reason and an expiry, and
# end them when they no longer hold. FindingDecision is the row; this module is every way one is written.
#
# By an operator (FindingDecisionsController), each in one transaction holding the hosts' rows in id order, as the
# matcher's transitions take them, so a decision and the re-triage of its findings commit together and never race a
# host's transitions:
# - record!: one action for one advisory on up to MAX_HOSTS hosts (N8), each with its own decision, evidence, and audit
#   entry, all with the request's id. Only on hosts where the advisory's open findings are in Needs attention or Low
#   risk (none in Fix available), at most FLEET_DECISION_MAX_DAYS (90) days, or FLEET_DECISION_MAX_DAYS_KEV (30) for
#   an advisory on CISA's KEV list; a control confirmed host by host. More than STEP_UP_ABOVE hosts needs the
#   second factor (epic decision 14; the controller checks it).
# - change!: a new reason or expiry, still within the limit counted from the day it was recorded (a decision is
#   never extended for ever: a longer one is a new decision, on today's evidence).
# - end!: ended by the operator.
# Each re-triages the advisory's findings on its hosts at once (VulnerabilityMatcher.retriage!: a decision moves no
# other finding), so the tab shows the new bucket when the page reloads.
#
# By the system (FindingDecisions::Lifecycle), audited as the system:
# - expired, the day after expires_on (FindingDecisionExpiryJob, hourly; the control source already stops applying
#   a control on that day);
# - suspended, when the evidence gets worse than recorded: a CVE of the advisory added to KEV, its EPSS band
#   becoming high, or its severity rising. Checked in every host's transitions and triage re-runs (so a KEV listing
#   suspends at once, in the run it starts) and hourly for every active decision;
# - ended when a fix appears (a finding it covers in K1, K2, F1, or F2) or when every finding it covers resolves,
#   in the host's transitions.
# A suspended or ended decision stays visible with why; the finding is then due a new decision.
module FindingDecisions
  STEP_UP_ABOVE = 10
  MAX_HOSTS = 50
  # Active decisions this close to their last day are listed as due (VT-D05).
  EXPIRING_WITHIN = 7
  ALLOWED_BUCKETS = %w[attention low_risk].freeze
  FIX_RULES = %w[K1 K2 F1 F2].freeze
  # Severity for "the severity rising": an unknown severity counts as medium, as rule N4 counts it.
  SEVERITY_RANK = { "critical" => 4, "high" => 3, "medium" => 2, "unknown" => 2, "low" => 1 }.freeze
  # The epic's VT-M3 points per advisory (critical, high, medium, low or unknown), for the saved notice's "points went
  # from ... to ..." of the advisory on the host. A KEV-listed advisory scores double, except in Ignorable.
  POINTS = { "attention" => [ 40, 20, 8, 2 ], "fix" => [ 20, 10, 4, 1 ], "control" => [ 10, 5, 2, 1 ], "low_risk" => [ 2, 1, 0, 0 ], "ignorable" => [ 0, 0, 0, 0 ] }.freeze

  # An advisory's exploitation and severity signals now, as the rules read them (stored data, whatever its age).
  Signals = Data.define(:severity, :cvss_av, :cvss_pr, :cvss_ui, :kev_cves, :epss_high, :epss_score) do
    def kev? = kev_cves.any?
    def epss_band = epss_high ? "high" : (epss_score ? "normal" : nil)
  end

  # What record!, change!, and end! did: the decisions written, or the problems found ({ field => sentence }), and the
  # candidates the form shows again.
  Outcome = Data.define(:decisions, :errors, :candidates) do
    def saved? = errors.empty?
  end

  class Refused < StandardError; end

  module_function

  def config = Rails.configuration.x.finding_decisions

  def max_days(kev) = kev ? config.max_days_kev : config.max_days

  # The last day a decision may run to: from (the day it is recorded) plus the limit.
  def last_day(kev:, from: Date.current) = from + max_days(kev)

  # { advisory id => Signals } for the advisories, in three queries.
  def signals(advisory_ids)
    advisories = Advisory.where(id: advisory_ids.uniq).pluck(:id, :advisory_id, :aliases, :severity, :cvss_av, :cvss_pr, :cvss_ui)
    cves = advisories.to_h { |id, name, aliases, *| [ id, VulnerabilityTriage::Base.cve_ids(name, aliases) ] }
    all = cves.values.flatten.uniq
    kev = all.empty? ? Set.new : KevEntry.where(cve_id: all).pluck(:cve_id).to_set
    epss = all.empty? ? {} : EpssScore.where(cve_id: all).pluck(:cve_id, :score, :band).to_h { |cve, score, band| [ cve, [ score, band ] ] }
    advisories.to_h do |id, _, _, severity, av, pr, ui|
      list = cves.fetch(id)
      scores = epss.values_at(*list).compact
      [ id, Signals.new(severity:, cvss_av: av, cvss_pr: pr, cvss_ui: ui, kev_cves: list.select { |c| kev.include?(c) },
                        epss_high: scores.any? { |_, band| band == "high" }, epss_score: scores.map(&:first).max) ]
    end
  end

  # What got worse than the evidence recorded, as { field => [recorded, now] } (empty when nothing did): a CVE added to
  # KEV, the EPSS band becoming high, or the severity rising.
  def worsened(evidence, signals)
    changes = {}
    changes["kev"] = [ false, true ] if signals.kev? && !evidence["kev"]
    changes["epss_band"] = [ evidence["epss_band"], "high" ] if signals.epss_high && evidence["epss_band"] != "high"
    if SEVERITY_RANK.fetch(signals.severity, 2) > SEVERITY_RANK.fetch(evidence["severity"].to_s, 2)
      changes["severity"] = [ evidence["severity"], signals.severity ]
    end
    changes
  end

  # The points of one advisory on a host in a bucket ("control" for O1), by the epic's VT-M3 table.
  def points(bucket, severity, kev)
    index = { "critical" => 0, "high" => 1, "medium" => 2 }.fetch(severity, 3)
    value = POINTS.fetch(bucket)[index]
    kev && bucket != "ignorable" ? value * 2 : value
  end

  # Records one decision per chosen host. params: kind, reason, expires_on (a "YYYY-MM-DD" text), host_ids,
  # confirmed_ids (the hosts whose control the operator confirmed). host: the host the form was opened from.
  def record!(operator:, host:, advisory:, params:, today: Date.current)
    kind = params[:kind].to_s
    reason = FindingDecision.sanitize_reason(params[:reason])
    chosen = Array(params[:host_ids]).map(&:to_s).grep(/\A[1-9]\d{0,18}\z/).map(&:to_i).uniq
    confirmed = Array(params[:confirmed_ids]).map(&:to_s).grep(/\A[1-9]\d{0,18}\z/).to_set(&:to_i)
    candidates = Candidates.load(advisory, ([ host.id ] + chosen).uniq)
    signals = signals([ advisory.id ]).fetch(advisory.id)
    errors = {}
    errors[:kind] = "Choose whether a control is in place or the risk is accepted." unless FindingDecision::KINDS.include?(kind)
    reason_problem(reason)&.then { |problem| errors[:reason] = problem }
    expires_on, problem = expiry(params[:expires_on], kev: signals.kev?, from: today, today:)
    errors[:expires_on] = problem if problem
    errors[:hosts] = "Choose at least one host." if chosen.empty?
    errors[:hosts] = "Choose at most #{MAX_HOSTS} hosts in one action." if chosen.size > MAX_HOSTS
    by_host = candidates.index_by { |c| c.host.id }
    chosen.each do |id|
      candidate = by_host[id]
      next errors[:"host_#{id}"] = "This host cannot be chosen." unless candidate
      next errors[:"host_#{id}"] = "#{candidate.host.name}: #{candidate.problem}" if candidate.problem
      next unless kind == "control" && !confirmed.include?(id)

      firewall = candidate.firewall == false ? " Its firewall is disabled." : ""
      errors[:"confirm_#{id}"] = "Confirm the control on #{candidate.host.name}, or untick #{candidate.host.name}.#{firewall}"
    end
    return Outcome.new(decisions: [], errors:, candidates:) if errors.any?

    decisions = write!(operator:, advisory:, kind:, reason:, expires_on:, host_ids: chosen, signals:)
    Outcome.new(decisions:, errors: {}, candidates:)
  rescue Refused => e
    Outcome.new(decisions: [], errors: { hosts: e.message }, candidates:)
  end

  # A new reason or expiry for an active decision, within the limit from the day it was recorded.
  def change!(decision, operator:, params:, today: Date.current)
    reason = FindingDecision.sanitize_reason(params[:reason])
    errors = {}
    reason_problem(reason)&.then { |problem| errors[:reason] = problem }
    expires_on, problem = expiry(params[:expires_on], kev: decision.evidence["kev"], from: decision.created_at.to_date, today:)
    errors[:expires_on] = problem if problem
    return Outcome.new(decisions: [], errors:, candidates: []) if errors.any?

    changed = locked(decision) do |current|
      raise Refused, "This decision has ended; record a new one." unless current.active?

      changes = { "reason" => [ current.reason, reason ], "until" => [ current.expires_on.iso8601, expires_on.iso8601 ] }.reject { |_, (a, b)| a == b }
      raise Refused, "Nothing changed: edit the reason or the date, or cancel." if changes.empty?

      current.update!(reason:, expires_on:)
      Audit.record(actor: operator, action: Audit::Actions::VULNERABILITY_DECISION_CHANGED, target: current.host,
                   changes: identity(current).merge(changes))
      current
    end
    Outcome.new(decisions: [ changed ], errors: {}, candidates: [])
  rescue Refused => e
    Outcome.new(decisions: [], errors: { base: e.message }, candidates: [])
  end

  # Ends an active decision by the operator, and re-triages its findings.
  def end!(decision, operator:, now: Time.current)
    locked(decision) do |current|
      raise Refused, "This decision has already ended." unless current.active?

      current.update!(ended_at: now, ended_by: operator, ended_why: "operator")
      Audit.record(actor: operator, action: Audit::Actions::VULNERABILITY_DECISION_ENDED, target: current.host,
                   changes: identity(current).merge("ended_why" => "operator", "bucket" => effect_on_end(current)))
      VulnerabilityMatcher.retriage!([ current.host_id ], advisory_ids: [ current.advisory_id ])
      Outcome.new(decisions: [ current ], errors: {}, candidates: [])
    end
  rescue Refused => e
    Outcome.new(decisions: [], errors: { base: e.message }, candidates: [])
  end

  # What every audit entry of a decision names: the decision, its advisory, and its kind.
  def identity(decision)
    { "decision_id" => decision.id, "advisory" => decision.advisory.advisory_id, "decision_kind" => decision.kind_name.downcase }
  end

  # What ending a decision does to its findings' bucket, for the audit entry: a control returns them to the bucket
  # recorded as its evidence; an acceptance changes none.
  def effect_on_end(decision)
    return nil unless decision.control?

    [ "low risk", VulnerabilityTriage::BUCKET_NAMES.fetch(decision.evidence["bucket"], "the rules' bucket").downcase ]
  end

  # The evidence sentence of the audit log: "critical; network, no login, no user action; not KEV; EPSS 0.04;
  # listening on the network".
  def evidence_words(evidence)
    vector = evidence["attack_vector"]
    av, pr, ui = vector.to_s.scan(/(?:AV|PR|UI):(\w)/).flatten if vector
    [
      evidence["severity"],
      (vector ? VulnerabilityTriage::Reasons.vector_words(av, pr, ui) : "no CVSS vector"),
      (evidence["kev"] ? "KEV" : "not KEV"),
      (evidence["epss_score"] ? "EPSS #{evidence['epss_score']}" : "no EPSS score"),
      Candidates::LISTENING.fetch(evidence["listening"], "listening not known")
    ].join("; ")
  end

  # "known exploited: no, now yes; severity: medium, now high", for the audit log and the tab.
  def changes_words(changes)
    names = { "kev" => "known exploited", "epss_band" => "EPSS band", "severity" => "severity" }
    word = ->(value) { value == true ? "yes" : value == false ? "no" : (value || "none").to_s }
    changes.map { |field, (before, after)| "#{names.fetch(field, field)}: #{word.(before)}, now #{word.(after)}" }.join("; ")
  end

  def reason_problem(reason)
    return "Say what the control is or why the risk is acceptable, in at least #{FindingDecision::REASON_LENGTH.min} characters." if reason.length < FindingDecision::REASON_LENGTH.min
    return "Keep it to #{ActiveSupport::NumberHelper.number_to_delimited(FindingDecision::REASON_LENGTH.max)} characters (this is #{ActiveSupport::NumberHelper.number_to_delimited(reason.length)})." if reason.length > FindingDecision::REASON_LENGTH.max

    nil
  end

  # [date, problem]: the expiry typed, checked against today and the limit counted from from.
  def expiry(text, kev:, from:, today:)
    date = text.to_s.match?(/\A\d{4}-\d{2}-\d{2}\z/) ? (Date.iso8601(text.to_s) rescue nil) : nil # rubocop:disable Style/RescueModifier
    last = last_day(kev:, from:)
    days = max_days(kev)
    limit = "Pick a date no later than #{last.iso8601} (#{days} days from #{from == today ? 'today' : "#{from.iso8601}, when it was recorded"}#{', since it is known exploited' if kev})."
    return [ nil, "Pick the last day the decision applies, as a date." ] unless date
    return [ nil, "Pick today or a later date." ] if date < today
    return [ nil, limit ] if date > last

    [ date, nil ]
  end

  # Writes the decisions under the hosts' locks, checking each host again there, then re-triages the advisory's
  # findings on them in the same transaction.
  def write!(operator:, advisory:, kind:, reason:, expires_on:, host_ids:, signals:)
    FindingDecision.transaction do
      ids = Host.lock.in_fleet.where(id: host_ids).order(:id).pluck(:id)
      raise Refused, "A host chosen was retired meanwhile; nothing was saved." unless ids.size == host_ids.size

      candidates = Candidates.load(advisory, ids, signals:)
      if (stale = candidates.find(&:problem))
        raise Refused, "#{stale.host.name}: #{stale.problem} Nothing was saved."
      end

      decisions = candidates.map do |candidate|
        decision = FindingDecision.create!(host: candidate.host, advisory:, kind:, reason:, expires_on:, created_by: operator,
                                           confirmed: kind == "control", evidence: candidate.evidence, request_id: Current.request_id)
        before = VulnerabilityTriage::BUCKET_NAMES.fetch(candidate.bucket).downcase
        Audit.record(actor: operator, action: Audit::Actions::VULNERABILITY_DECISION_RECORDED, target: candidate.host,
                     changes: identity(decision).merge("reason" => reason, "until" => expires_on.iso8601,
                                                       "bucket" => (kind == "control" ? [ before, "low risk" ] : nil),
                                                       "evidence" => evidence_words(decision.evidence),
                                                       "confirmed_for" => (candidate.host.name if kind == "control")).compact)
        decision
      end
      VulnerabilityMatcher.retriage!(ids, advisory_ids: [ advisory.id ])
      decisions
    end
  rescue ActiveRecord::RecordNotUnique
    raise Refused, "A host chosen got a decision for this advisory meanwhile; nothing was saved."
  end

  # Yields the decision locked, under its host's lock (taken first, as the transitions take it).
  def locked(decision)
    FindingDecision.transaction do
      Host.lock.where(id: decision.host_id).pluck(:id)
      yield decision.lock!
    end
  end

  private_class_method :write!, :locked
end
