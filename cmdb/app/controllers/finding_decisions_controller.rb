# Recording, changing, and ending a decision on a host's finding (VT-OVERRIDES #261, VT-D05, FR-2.6, FR-S.3; approved
# mockup vuln-triage/override.html). A page per decision, as the Phase 1 host actions: GET draws it, a CSRF-protected
# POST does it, and a refused POST draws it again with every problem in place (422) and nothing saved.
#
# - new / create: one advisory on the host the page was opened from, and on other hosts with the same open finding
#   (each listed with its own evidence; at most FindingDecisions::MAX_HOSTS in one action). A control must be
#   confirmed host by host. More than FindingDecisions::STEP_UP_ABOVE hosts needs the second factor (epic decision 14),
#   checked on the server whatever the form sent.
# - edit / update / end_decision: one decision of the host: a new reason or date, or its end.
#
# Any signed-in, allowlisted operator may decide (the dashboard has no roles); the host must be in the fleet, every
# chosen host is checked again on the server under its row lock, and every write is audited with the operator
# (FindingDecisions). Operator text is escaped wherever it is shown.
class FindingDecisionsController < ApplicationController
  before_action :load_host
  before_action :load_advisory, only: %i[new create]
  before_action :load_decision, only: %i[edit update end_decision]

  def new
    @form = { kind: FindingDecision::KINDS.include?(params[:kind]) ? params[:kind] : "control", reason: "", host_ids: [ @host.id ], confirmed_ids: [] }
    load_form
    @form[:expires_on] = FindingDecisions.last_day(kev: @signals.kev?).iso8601
  end

  def create
    @form = form_params
    chosen = Array(@form[:host_ids]).uniq
    if chosen.size > FindingDecisions::STEP_UP_ABOVE
      @second_factor_result = SecondFactors.step_up(operator_session: Current.operator_session, code: params[SecondFactorRequired::PARAM], purpose: "record_decisions")
      unless @second_factor_result.passed?
        @errors = { second_factor_code: "Choosing more than #{FindingDecisions::STEP_UP_ABOVE} hosts needs a code from your authenticator app: #{STEP_UP_PROBLEMS.fetch(@second_factor_result.status)}." }
        load_form
        return render(:new, status: @second_factor_result.status == :locked ? :too_many_requests : :forbidden)
      end
    end

    outcome = FindingDecisions.record!(operator: current_operator, host: @host, advisory: @advisory, params: @form)
    if outcome.saved?
      redirect_to vulnerabilities_host_path(@host, anchor: "attn"), notice: saved_notice(outcome.decisions)
    else
      @errors = outcome.errors
      load_form
      render :new, status: :unprocessable_content
    end
  end

  def edit
    @form = { reason: @decision.reason, expires_on: @decision.expires_on.iso8601 }
  end

  def update
    @form = params.permit(:reason, :expires_on).to_h.symbolize_keys
    outcome = FindingDecisions.change!(@decision, operator: current_operator, params: @form)
    if outcome.saved?
      redirect_to vulnerabilities_host_path(@host, anchor: "attn"), notice: "Decision changed for #{@host.name}: #{@advisory.advisory_id} until #{outcome.decisions.first.expires_on.iso8601}. Its bucket, points, and tier are unchanged."
    else
      @errors = outcome.errors
      render :edit, status: :unprocessable_content
    end
  end

  def end_decision
    outcome = FindingDecisions.end!(@decision, operator: current_operator)
    if outcome.saved?
      what = @decision.control? ? "It no longer counts as a control: the finding is back in the bucket the rules give it." : "The finding is due a decision again; its bucket, points, and tier are unchanged."
      redirect_to vulnerabilities_host_path(@host, anchor: "attn"), notice: "Decision ended for #{@host.name} on #{@advisory.advisory_id}. #{what}"
    else
      @form = { reason: @decision.reason, expires_on: @decision.expires_on.iso8601 }
      @errors = outcome.errors
      render :edit, status: :unprocessable_content
    end
  end

  STEP_UP_PROBLEMS = {
    not_enrolled: "you have no second factor set up", code_required: "type a code", expired: "the check ran out, type a new code",
    wrong: "that code was not accepted", reused: "that code was already used", locked: "your second factor is locked after too many wrong codes"
  }.freeze

  private

  def load_host
    @host = Host.in_fleet.find(params[:id]) # a retired host has nothing left to decide
  end

  def load_advisory
    @advisory = Advisory.find(params.require(:advisory_id).to_s[/\A[1-9]\d{0,18}\z/] || raise(ActiveRecord::RecordNotFound))
  end

  def load_decision
    @decision = FindingDecision.preload(:advisory, :created_by, :ended_by).find_by!(id: params[:decision_id], host_id: @host.id)
    @advisory = @decision.advisory
  end

  # The hosts the page lists: this one first, then up to Candidates::OTHERS others with the same open finding, then any
  # the form chose that are not among them (so a problem with one is shown beside it).
  def load_form
    others = FindingDecisions::Candidates.other_host_ids(@advisory, except: @host.id)
    chosen = Array(@form[:host_ids]) - [ @host.id ] - others
    @signals = FindingDecisions.signals([ @advisory.id ]).fetch(@advisory.id)
    @candidates = FindingDecisions::Candidates.load(@advisory, [ @host.id, *others, *chosen.first(FindingDecisions::MAX_HOSTS) ], signals: @signals)
    @this = @candidates.find { |c| c.host.id == @host.id }
    @others_capped = others.size >= FindingDecisions::Candidates::OTHERS
    @errors ||= {}
  end

  def form_params
    permitted = params.permit(:kind, :reason, :expires_on, host_ids: [], confirmed_ids: [])
    ids = ->(key) { Array(permitted[key]).map(&:to_s).grep(/\A[1-9]\d{0,18}\z/).map(&:to_i).uniq }
    { kind: permitted[:kind].to_s, reason: permitted[:reason].to_s.first(4_000), expires_on: permitted[:expires_on].to_s.first(32),
      host_ids: ids.(:host_ids), confirmed_ids: ids.(:confirmed_ids) }
  end

  # What was saved and what it changed (mockup override.html, "Saved"): read back from the findings, so it never says a
  # finding moved before its re-triage did. Points are the advisory's on the host, by the epic's VT-M3 table.
  def saved_notice(decisions)
    decision = decisions.find { |d| d.host_id == @host.id } || decisions.first
    on = decisions.size == 1 ? decision.host.name : "#{pluralize(decisions.size, 'host')} (each with its own decision and audit entry)"
    evidence = decision.evidence
    rules = VulnerabilityFinding.active.where(host_id: decision.host_id, advisory_id: @advisory.id).pluck(:bucket_rule).map { |r| VulnerabilityTriage.rule_for(r) }
    before = FindingDecisions.points(evidence["bucket"], evidence["severity"], evidence["kev"])
    head = "Decision saved for #{on}."
    if decision.control?
      after = FindingDecisions.points("control", evidence["severity"], evidence["kev"])
      moved = rules.include?("O1") ? "is now in Low risk with \"Control in place\"" : "moves to Low risk with \"Control in place\" when its re-triage runs, in a few seconds,"
      kev = evidence["kev"] ? " It keeps its \"Known exploited\" tier." : ""
      "#{head} #{@advisory.advisory_id} #{moved} until #{decision.expires_on.iso8601} on #{decision.host.name}. Its points there go from #{before} to #{after} " \
        "(a #{evidence['severity']} advisory in #{VulnerabilityTriage::BUCKET_NAMES.fetch(evidence['bucket'])} is #{before} points; under a control it is #{after}).#{kev}"
    else
      "#{head} #{@advisory.advisory_id} is marked \"Risk accepted\" until #{decision.expires_on.iso8601} and is no longer listed as due. " \
        "No change to its bucket, points (#{before}), or tier: accepting a risk changes nothing about exposure."
    end
  end

  def pluralize(count, word) = ActionController::Base.helpers.pluralize(count, word)
end
