# Creating a task (FR-3.4, P3-S08; mockups create-type.html, create-params.html, create-targets.html,
# create-confirm.html, and create-blocked.html, owner decisions Q3 to Q13). Four short GET steps with no JavaScript
# (Q3): the type, its parameters, the targets, and the confirmation. They write nothing, and each one checks again
# everything chosen before it, so a step reached by a hand-made URL shows the same errors as one reached by the form.
#
# The confirmation's form POSTs to create, which needs a recent second factor ("create_task", Q11) and the page's
# signed confirmation (TaskConfirmation): the request must be the one the page drew, under 30 minutes ago, and the
# hosts it resolves to on submit must be the ones it showed (Q13), or nothing is created and the confirmation is
# drawn again with the reason. TaskBatches.create! then applies every rule again, so the pages are a convenience and
# the server is the control: a forged POST gets the same validation as the form. Every refused POST is audited as
# task.creation_refused, with the operator as actor.
#
# The form never has a free-text field that reaches a task: types are radio buttons from the catalog, the restart
# service is a list from the allowlist (Q5), and hosts are a tag or ticked boxes.
class TaskCreationsController < ApplicationController
  # Request keys that belong to the form, not to the task request: everything else in a POST goes to TaskBatches,
  # which refuses what it does not accept (such as a "command" field) rather than ignoring it.
  FORM_KEYS = %w[controller action authenticity_token second_factor_code confirmation commit].freeze
  # Hosts listed for picking at once; narrow with the search box.
  PICK_LIMIT = 100

  helper_method :task_request

  require_second_factor "create_task", only: :create
  before_action :require_enrolled_second_factor, except: :create
  before_action :load_entry, only: %i[parameters targets confirm]

  # Step 1: choose the type.
  def type
    @choices = TaskCreation.choices
    @carried = task_request.slice("target")
  end

  # Step 2: its parameters, chosen from fixed lists.
  def parameters
    @choice = TaskCreation.choice(@entry)
    @chosen = task_request["parameters"].is_a?(Hash) ? task_request["parameters"] : {}
    @services = TaskCreation.services if @entry.type == "restart_service"
  end

  # Step 3: the targets. Checks the parameters first; with a selection (a tag, or picked hosts), shows the hosts it
  # resolves to and the hosts left out, with why.
  def targets
    return if parameters_refused?

    load_targets
  end

  # Step 4: the confirmation. Everything is checked again; a refusal goes back to the targets step.
  def confirm
    return if parameters_refused?

    @request = task_request.slice(*TaskConfirmation::REQUEST_KEYS)
    @preview = TaskBatches.preview(@request)
    return render_targets(errors: [], status: :unprocessable_content) if @preview.targeted.empty?

    @token = TaskConfirmation.issue(@request, @preview.targeted_ids, operator: current_operator)
  rescue TaskBatches::Refused => e
    render_targets(errors: e.errors, status: :unprocessable_content)
  end

  # Create the batch: one task per targeted host (TaskBatches.create!).
  def create
    @request = task_request.except(*FORM_KEYS)
    verified = TaskConfirmation.verify(params[:confirmation], @request, operator: current_operator)
    return refuse(confirmation_problems(verified), verified:) unless verified.ok?

    existing = TaskBatch.find_by(confirmation_token: verified.nonce)
    return redirect_to_existing(existing) if existing

    result = TaskBatches.create!(@request, operator: current_operator, expected_host_ids: verified.host_ids, confirmation_token: verified.nonce)
    redirect_to task_batch_path(result.batch), notice: created_notice(result)
  rescue TaskBatches::Refused => e
    refuse(e.errors, verified:)
  rescue ActiveRecord::RecordNotUnique
    # The same confirmation submitted twice at once: the other request created the batch.
    redirect_to_existing(TaskBatch.find_by!(confirmation_token: verified.nonce))
  end

  private

  # Q12: without a second factor the flow is replaced by an explanation; create refuses on its own as well.
  def require_enrolled_second_factor
    render :no_second_factor if second_factor_result.status == :not_enrolled
  end

  def load_entry
    type = params[:type]
    return redirect_to(new_task_path, alert: "Choose a task type.") if type.blank?
    return redirect_to(new_task_path, alert: "That is not a task type in the catalog. Choose one of these.") unless type.is_a?(String) && TaskCatalog.current.type?(type)

    @entry = TaskCatalog.current.entry(type)
  end

  # The parameters step again, with the errors in place, when the parameters fail the catalog schema or the server's
  # policy (TaskPolicy). Returns whether it did.
  def parameters_refused?
    refusal = TaskPolicy.refusal(@entry.type, task_request["parameters"])
    return false unless refusal

    @parameter_errors = refusal.errors
    parameters
    render :parameters, status: :unprocessable_content
    true
  end

  # The targets step's selection: by tag or by picking hosts, from the step's own form (by, tag, host_ids) or from
  # a target carried back from the confirmation (target[tag] or target[host_ids][]).
  def load_targets
    carried = task_request["target"].is_a?(Hash) ? task_request["target"] : {}
    @by = params[:by].presence_in(%w[tag hosts]) || (carried.key?("host_ids") ? "hosts" : "tag")
    @tag = (params.key?(:by) ? params[:tag] : carried["tag"]).presence
    @picked_ids = (params.key?(:by) ? Array(params[:host_ids]) : Array(carried["host_ids"])).filter_map { |id| integer(id) }
    @query = params[:q].to_s.first(100)
    @tags = TaskCreation.tags
    @capable = TaskCreation.capable_hosts(@entry).exists?
    @parameters = task_request["parameters"].slice(*@entry.parameter_names) # checked already (parameters_refused?)
    @allowlist = TaskPolicy.restart_allowlist if @entry.type == "restart_service"
    @pickable = (TaskCreation.pickable_hosts(@query, limit: PICK_LIMIT) | Host.where(id: @picked_ids).to_a).sort_by { |host| [ host.name, host.id ] } if @by == "hosts"
    @target = if @by == "tag" then { "tag" => @tag } if @tag
    elsif @picked_ids.any? then { "host_ids" => @picked_ids }
    end
    return unless @target

    @preview = TaskBatches.preview({ "type" => @entry.type, "parameters" => @parameters, "target" => @target })
  rescue TaskBatches::Refused => e
    @target_errors = e.errors
  end

  def render_targets(errors:, status:)
    load_targets
    @target_errors = errors if errors.any?
    render :targets, status:
  end

  # A refused POST: audited, then the confirmation drawn again with the reasons and a new token, or, when the request
  # is not one the confirmation can draw, a page that says why.
  def refuse(problems, verified: nil, status: :unprocessable_content)
    record_refusal(problems)
    response.headers["Cache-Control"] = "no-store"
    @errors = problems
    @verified = verified
    @request = task_request.slice(*TaskConfirmation::REQUEST_KEYS)
    @preview = TaskBatches.preview(@request)
    @entry = @preview.entry
    raise TaskBatches::Refused, [ { "pointer" => "/target", "problem" => "selects no host that can run this task type now" } ] if @preview.targeted.empty?

    @token = TaskConfirmation.issue(@request, @preview.targeted_ids, operator: current_operator)
    @typed_count = params[:confirm_host_count].to_s.first(16)
    render :confirm, status:
  rescue TaskBatches::Refused => e
    @errors |= e.errors
    render :refused, status:
  end

  # A code that was missing, wrong, or locked: refused like any other problem, with the confirmation drawn again so
  # nothing typed is lost (SecondFactorRequired). The typed count is checked too, so both problems show at once.
  def second_factor_refused(result)
    problems = [ { "pointer" => "/second_factor_code", "problem" => second_factor_problem(result.status) } ]
    count = count_problem
    problems << count if count
    refuse(problems, status: result.status == :locked ? :too_many_requests : :forbidden)
  end

  def second_factor_problem(status)
    {
      not_enrolled: "is not set up, so tasks cannot be created", code_required: "is needed: type a code from your authenticator app",
      expired: "check ran out: type a new code", wrong: "code was not accepted", reused: "code was already used", locked: "is locked after too many wrong codes"
    }.fetch(status)
  end

  # The typed-count problem the request would get, if the count is wrong, for showing beside a refused code.
  def count_problem
    preview = TaskBatches.preview(task_request.except(*FORM_KEYS))
    count = task_request["confirm_host_count"]
    return if preview.targeted.size <= TaskBatches::CONFIRM_ABOVE || count == preview.targeted.size

    { "pointer" => "/confirm_host_count", "problem" => "must be #{preview.targeted.size}, the number of hosts this batch will run on" }
  rescue TaskBatches::Refused
    nil
  end

  # Why a confirmation was not accepted, followed by whatever TaskBatches finds wrong with the request itself, so a
  # forged POST without a confirmation still learns what the form would have said.
  def confirmation_problems(verified)
    problem = {
      missing: "is missing: create tasks from the confirmation page", invalid: "is not valid: confirm on the confirmation page again",
      expired: "is over #{TaskConfirmation::MAX_AGE.in_minutes.to_i} minutes old", changed: "was drawn for a different request"
    }.fetch(verified.status)
    problems = [ { "pointer" => "/confirmation", "problem" => problem } ]
    TaskBatches.preview(@request)
    problems
  rescue TaskBatches::Refused => e
    problems + e.errors
  end

  # task.creation_refused: the operator, the type if it is one in the catalog, and the problems as sentences. Values
  # from the request are never recorded, only where the problem was (P3-S07, mockup audit.html).
  def record_refusal(problems)
    type = task_request["type"]
    AuditEntry.transaction do
      Audit.record(actor: current_operator, action: Audit::Actions::TASK_CREATION_REFUSED, changes: {
        "task_type" => (type if type.is_a?(String) && TaskCatalog.current.type?(type)),
        "problems" => problems.map { |problem| "#{problem['pointer'].presence || '/'} #{problem['problem']}" }
      }.compact)
    end
  end

  def redirect_to_existing(batch)
    redirect_to task_batch_path(batch), notice: "Nothing new was created: this confirmation was already used for batch #{batch.id} at #{helpers.utc(batch.created_at)}."
  end

  def created_notice(result)
    "Created #{helpers.pluralize(result.tasks.size, 'task')} in batch #{result.batch.id}. Each host picks up its task when its agent next asks for work. Recorded in the audit log."
  end

  # The request in the shape TaskBatches takes: string keys, form strings turned into the integers the API uses
  # where they are whole numbers (host ids, the typed count) and left as sent otherwise, so TaskBatches refuses them.
  # A type without parameters sends no parameters field, which is {}.
  def task_request
    @task_request ||= begin
      request = params.to_unsafe_h.to_hash
      request["parameters"] = {} unless request.key?("parameters")
      target = request["target"]
      target["host_ids"] = target["host_ids"].map { |id| integer(id) || id } if target.is_a?(Hash) && target["host_ids"].is_a?(Array)
      if request.key?("confirm_host_count")
        count = request["confirm_host_count"]
        count.blank? ? request.delete("confirm_host_count") : request["confirm_host_count"] = integer(count) || count
      end
      request
    end
  end

  # A positive whole number from a form string (or one already converted), or nil.
  def integer(value)
    return value if value.is_a?(Integer) && value.positive?

    value.to_i if value.is_a?(String) && value.match?(/\A[1-9]\d{0,17}\z/)
  end
end
