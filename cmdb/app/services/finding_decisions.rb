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
#   an advisory on CISA's KEV list; a control confirmed host by host.
# - The second factor (owner decision 2026-11-23, epic decision 37, replacing decision 14's "one action"; clarified to
#   per operator to meet its purpose, review of #299): a decision on an advisory on CISA's KEV list needs a fresh code
#   every time; any other needs one once the operator has recorded more than STEP_UP_ABOVE host decisions within
#   STEP_UP_WINDOW, in any of their sessions, counted on the server under the operator's row lock, so neither splitting
#   an action nor signing in again avoids it. The controller asks for the code (step_up_needed?); write! checks the
#   count and the KEV status again under the locks and refuses (StepUpNeeded) when the code it needs was not given: a
#   fresh one (:fresh) on a KEV-listed advisory, any (:fresh or :window) otherwise.
# - change!: a new reason or expiry, still within the limit counted from the day it was recorded (a decision is
#   never extended for ever: a longer one is a new decision, on today's evidence). On a KEV-listed advisory it needs
#   a fresh code too. A decision whose evidence got worse since it was recorded is suspended instead of changed, as the
#   sweep would suspend it.
# - end!: ended by the operator.
# A decision past its last day that the hourly job has not ended yet is never changed or ended by the operator: either
# expires it there and then (audited as expired) and says so, so it cannot be revived.
# Each re-triages the advisory's findings on its hosts at once (VulnerabilityMatcher.retriage!: a decision moves no
# other finding), so the tab shows the new bucket when the page reloads.
#
# By the system (FindingDecisions::Lifecycle), audited as the system:
# - expired, the day after expires_on (FindingDecisionExpiryJob, hourly; the control source already stops applying
#   a control on that day);
# - suspended, when the evidence gets worse than recorded: a CVE of the advisory added to KEV, its EPSS band
#   becoming high, or its severity rising (any CVE of the advisory newly on the list, compared as lists). Checked in every host's transitions and triage re-runs (so a KEV listing
#   suspends at once, in the run it starts) and hourly for every active decision;
# - ended when a fix appears (a finding it covers in K1, K2, F1, or F2) or when every finding it covers resolves,
#   in the host's transitions.
# A suspended or ended decision stays visible with why; the finding is then due a new decision.
module FindingDecisions
  STEP_UP_ABOVE = 10
  STEP_UP_WINDOW = 15.minutes
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
  # The session's count under its lock needs the second factor, which this request did not pass.
  class StepUpNeeded < StandardError; end

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
    recorded = Array(evidence["kev_cves"])
    changes["kev_cves"] = [ recorded, signals.kev_cves ] if (signals.kev_cves - recorded).any?
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

  # Host decisions the operator recorded within STEP_UP_WINDOW, in any session.
  def recent_count(operator, now: Time.current) = FindingDecision.where(created_by_id: operator.id, created_at: (now - STEP_UP_WINDOW)..).count

  # Whether recording count more host decisions needs the second factor: always on a KEV-listed advisory, else when the
  # operator's count within the window would pass STEP_UP_ABOVE.
  def step_up_needed?(operator, count, kev:, now: Time.current) = kev || recent_count(operator, now:) + count > STEP_UP_ABOVE

  # Records one decision per chosen host. params: kind, reason, expires_on (a "YYYY-MM-DD" text), host_ids,
  # confirmed_ids (the hosts whose control the operator confirmed). host: the host the form was opened from.
  # operator_session: the session recording it (kept for the audit); stepped_up: false, or how this request passed
  # the second factor: :fresh (a code was checked now) or :window (the session's open 5-minute window).
  def record!(operator:, host:, advisory:, params:, operator_session: nil, stepped_up: false, today: Date.current)
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

    decisions = write!(operator:, advisory:, kind:, reason:, expires_on:, host_ids: chosen, signals:, operator_session:, stepped_up:)
    Outcome.new(decisions:, errors: {}, candidates:)
  rescue Refused => e
    Outcome.new(decisions: [], errors: { hosts: e.message }, candidates:)
  rescue StepUpNeeded => e
    Outcome.new(decisions: [], errors: { second_factor_code: e.message }, candidates:)
  end

  # A new reason or expiry for an active decision, within the limit from the day it was recorded.
  def change!(decision, operator:, params:, now: Time.current)
    today = now.to_date
    reason = FindingDecision.sanitize_reason(params[:reason])
    errors = {}
    reason_problem(reason)&.then { |problem| errors[:reason] = problem }
    expires_on, problem = expiry(params[:expires_on], kev: decision.evidence["kev"], from: decision.created_at.to_date, today:)
    errors[:expires_on] = problem if problem
    return Outcome.new(decisions: [], errors:, candidates: []) if errors.any?

    changed = locked(decision) do |current|
      raise Refused, "This decision has ended; record a new one." unless current.active?
      next Lifecycle.expire!(current, now:) && :lapsed if current.lapsed?(today)

      # Worse evidence since it was recorded: suspended, as the sweep would, rather than changed (review of #299).
      worse = worsened(current.evidence, signals([ current.advisory_id ]).fetch(current.advisory_id))
      next Lifecycle.suspend!(current, worse, now:) && [ :worse, worse ] if worse.any?

      changes = { "reason" => [ current.reason, reason ], "until" => [ current.expires_on.iso8601, expires_on.iso8601 ] }.reject { |_, (a, b)| a == b }
      raise Refused, "Nothing changed: edit the reason or the date, or cancel." if changes.empty?

      current.update!(reason:, expires_on:)
      Audit.record(actor: operator, action: Audit::Actions::VULNERABILITY_DECISION_CHANGED, target: current.host,
                   changes: identity(current).merge(changes))
      current
    end
    return Outcome.new(decisions: [], errors: { base: LAPSED }, candidates: []) if changed == :lapsed
    if changed.is_a?(Array)
      return Outcome.new(decisions: [], errors: { base: "The evidence got worse since it was recorded (#{changes_words(changed.last)}), so it is now suspended " \
                                                        "and the finding is due a new decision. Record a new one on today's evidence." }, candidates: [])
    end

    Outcome.new(decisions: [ changed ], errors: {}, candidates: [])
  rescue Refused => e
    Outcome.new(decisions: [], errors: { base: e.message }, candidates: [])
  end

  # Ends an active decision by the operator, and re-triages its findings.
  def end!(decision, operator:, now: Time.current)
    locked(decision) do |current|
      raise Refused, "This decision has already ended." unless current.active?
      next Outcome.new(decisions: [], errors: { base: LAPSED }, candidates: []) if current.lapsed?(now.to_date) && Lifecycle.expire!(current, now:)

      current.update!(ended_at: now, ended_by: operator, ended_why: "operator")
      before = buckets_of(current)
      VulnerabilityMatcher.retriage!([ current.host_id ], advisory_ids: [ current.advisory_id ])
      # The bucket read back after the re-triage, not the one recorded as evidence (the base may have moved since).
      bucket = [ before, buckets_of(current) ] if current.control?
      Audit.record(actor: operator, action: Audit::Actions::VULNERABILITY_DECISION_ENDED, target: current.host,
                   changes: identity(current).merge("ended_why" => "operator", "bucket" => bucket).compact)
      Outcome.new(decisions: [ current ], errors: {}, candidates: [])
    end
  rescue Refused => e
    Outcome.new(decisions: [], errors: { base: e.message }, candidates: [])
  end

  # What every audit entry of a decision names: the decision, its advisory, and its kind.
  def identity(decision)
    { "decision_id" => decision.id, "advisory" => decision.advisory.advisory_id, "decision_kind" => decision.kind_name.downcase }
  end

  LAPSED = "It passed its last day, so it has now ended as expired and the finding is due a new decision. Record a new one to go on.".freeze

  # The buckets of the decision's open findings on its host, as stored ("low risk", or "needs attention, ignorable").
  def buckets_of(decision)
    ids = VulnerabilityFinding.active.where(host_id: decision.host_id, advisory_id: decision.advisory_id).distinct.pluck(:bucket).compact.sort
    ids.map { |id| VulnerabilityTriage::BUCKET_NAMES.fetch(VulnerabilityTriage.bucket_for(id)).downcase }.join(", ").presence || "none open"
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
    names["kev_cves"] = "CVEs on the KEV list"
    word = lambda do |value|
      case value
      when true then "yes"
      when false then "no"
      when Array then value.empty? ? "none" : value.join(", ")
      else (value || "none").to_s
      end
    end
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
  def write!(operator:, advisory:, kind:, reason:, expires_on:, host_ids:, signals:, operator_session:, stepped_up:)
    FindingDecision.transaction do
      ids = Host.lock.in_fleet.where(id: host_ids).order(:id).pluck(:id)
      raise Refused, "A host chosen was retired meanwhile; nothing was saved." unless ids.size == host_ids.size

      # Under the operator's lock (after the hosts', as no other path takes both: the step-up takes it in a transaction
      # of its own, before), so two requests of one operator at once, from any sessions, are counted one after the
      # other and cannot each stay under the threshold.
      Operator.lock.where(id: operator.id).pluck(:id)
      now = signals([ advisory.id ]).fetch(advisory.id)
      raise Refused, "The advisory was added to CISA's KEV list meanwhile; check the date (at most #{max_days(true)} days) and save again." if now.kev? && !signals.kev?
      if step_up_needed?(operator, ids.size, kev: now.kev?) && !(stepped_up == :fresh || (stepped_up && !now.kev?))
        raise StepUpNeeded, "A decision on a known exploited advisory needs a new code from your authenticator app every time. Nothing was saved." if now.kev?

        raise StepUpNeeded, "You have recorded #{recent_count(operator)} host decisions in the last #{STEP_UP_WINDOW.in_minutes.to_i} minutes, in any session; " \
                            "more than #{STEP_UP_ABOVE} need a code from your authenticator app. Nothing was saved."
      end

      candidates = Candidates.load(advisory, ids, signals:)
      if (stale = candidates.find(&:problem))
        raise Refused, "#{stale.host.name}: #{stale.problem} Nothing was saved."
      end

      decisions = candidates.map do |candidate|
        decision = FindingDecision.create!(host: candidate.host, advisory:, kind:, reason:, expires_on:, created_by: operator,
                                           confirmed: kind == "control", evidence: candidate.evidence, request_id: Current.request_id,
                                           operator_session_id: operator_session&.id)
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

  private_class_method :write!, :locked, :buckets_of
end
