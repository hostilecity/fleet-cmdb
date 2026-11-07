# CIS-aligned rules (P2-D06, FR-2.2; approved mockups rules.html, rule.html, rule-create.html, rule-create-preview.html,
# rule-edit.html, rule-edit-preview.html, rule-edit-errors.html, dialogs.html).
#
# - index and show are read-only. The list is RuleList (filters and sort in the URL).
# - Adding and editing go form, Preview, Save (owner decisions Q11, Q12). Preview is a POST that writes nothing: it
#   checks the rule with the import's checks (RuleForm, CisRules::RuleFile.parse_rule) and shows CisDryRun's result.
#   The preview page carries what was typed in hidden fields, so Save saves exactly the rule that was previewed,
#   checked again. Saving goes through CisRule.define!, the import's path, under the rules' write lock: version 1
#   for a new rule (its key must still be unused), a new version for an edit (refused if someone else saved a
#   version since the edit began), audited with the operator as actor and the before and after values, and every
#   host re-evaluated by CisEvaluationJob once it commits. No agent is contacted (AC-2.2).
# - Enable and disable are a confirmation page (GET) and a CSRF-protected POST, audited and re-evaluated the same way.
class RulesController < ApplicationController
  CHANGE_LOG_LIMIT = 50

  before_action :load_rule, except: %i[index new preview_new create]

  def index
    @list = RuleList.new(params.permit(:q, :severity, :status, :applies, :result, :sort, :dir, :page))
  end

  def show
    @version = @rule.current_version
    @results = RuleResults.new(@rule)
    @entries = AuditEntry.for_target(@rule).order(occurred_at: :desc, id: :desc).limit(CHANGE_LOG_LIMIT + 1).to_a
    authored = AuditEntry.for_target(@rule).where(action: [ Audit::Actions::RULE_CREATED, Audit::Actions::RULE_EDITED ]).order(:occurred_at, :id).to_a
    @authors = version_authors(authored)
    @records = AuditLog::Records.for(@entries + authored)
    @fact_users = CisRuleVersion.where(id: CisRule.select(:current_version_id), fact: @version.fact).count
  end

  def new
    @form = RuleForm.blank
  end

  def preview_new
    @form = RuleForm.new(attributes: rule_params)
    return render(:new) if editing_again?
    return render(:new, status: :unprocessable_content) unless @form.valid?

    @preview = CisDryRun.call(@form.rule_hash).preview
    render :preview_new
  end

  def create
    @form = RuleForm.new(attributes: rule_params)
    return render(:new, status: :unprocessable_content) unless @form.valid?

    definition = CisRules::Definition.from_h(@form.rule_hash)
    created = CisRule.with_write_lock do
      next false if CisRule.exists?(key: definition.key)

      CisRule.define!(definition, actor: current_operator, enabled: @form.enabled?)
    end
    unless created
      @form.add_problem("key", "#{definition.key} was added by someone else since your preview; a key is never reused, so choose another")
      return render(:new, status: :unprocessable_content)
    end
    rule = CisRule.find_by!(key: definition.key)
    redirect_to rule_path(rule), notice: "Added #{rule.key}, version 1. #{rule.enabled ? 'Every host is checked against it now; no agent is contacted.' : 'It is disabled, so it is not evaluated until you enable it.'}"
  end

  def edit
    @form = RuleForm.for_rule(@rule)
    @base_version = @rule.current_version
  end

  def preview_edit
    @form = RuleForm.new(attributes: rule_params, rule: @rule)
    @base_version = base_version
    return render(:edit) if editing_again?
    return render(:edit, status: :unprocessable_content) unless @form.valid?
    return changed_meanwhile unless @base_version.id == @rule.current_version_id

    @preview = CisDryRun.call(@form.rule_hash).preview
    render :preview_edit
  end

  def update
    @form = RuleForm.new(attributes: rule_params, rule: @rule)
    @base_version = base_version
    return render(:edit, status: :unprocessable_content) unless @form.valid?

    outcome = CisRule.with_write_lock do
      @rule.reload
      next :conflict unless @rule.current_version_id == @base_version.id

      CisRule.define!(CisRules::Definition.from_h(@form.rule_hash), actor: current_operator)
    end
    case outcome
    when :conflict then changed_meanwhile
    when :unchanged
      redirect_to rule_path(@rule), notice: "No change: saving made no new version."
    else
      @rule.reload
      redirect_to rule_path(@rule), notice: "Saved as version #{@rule.current_version.version}. Every host's latest config snapshot is checked against it now; no agent is contacted."
    end
  end

  def confirm_disable
    @results = RuleResults.new(@rule)
  end

  def disable = set_enabled(false)

  def confirm_enable; end

  def enable = set_enabled(true)

  private

  def load_rule
    @rule = CisRule.includes(:current_version).find(params[:id])
    raise ActiveRecord::RecordNotFound, "rule has no version" unless @rule.current_version
  end

  def rule_params
    params.fetch(:rule, {}).permit(*RuleForm::TEXT_FIELDS, :operator, :expected, :condition_text, :enabled, platforms: %i[distribution versions]).to_h
  end

  # "Back to editing" on a preview: show the form again as typed, checking nothing.
  def editing_again? = params[:back].present?

  # The version the edit started from, carried through the preview, so a version saved meanwhile is not overwritten.
  def base_version
    id = params[:base_version_id].to_s
    @rule.versions.find_by(id: id.match?(/\A\d{1,18}\z/) ? id : nil) || @rule.current_version
  end

  # Someone saved a version after this edit began: show the form again, with what was typed, against the new version.
  def changed_meanwhile
    @rule.reload
    @form.add_problem("base", "The rule changed since you started editing: version #{@rule.current_version.version} was saved meanwhile. Your changes are kept below; " \
                              "preview them again against the new version.")
    @base_version = @rule.current_version
    render :edit, status: :conflict
  end

  def set_enabled(value)
    changed = CisRule.with_write_lock { @rule.lock!.public_send(value ? :enable! : :disable!, actor: current_operator) }
    word = value ? "enabled" : "disabled"
    message = if !changed then "#{@rule.key} was already #{word}."
    elsif value then "Enabled #{@rule.key}. Every host's latest config snapshot is checked against it now; no agent is contacted."
    else "Disabled #{@rule.key}. Its results become not evaluated; its history and versions are kept."
    end
    redirect_to rule_path(@rule), notice: message
  end

  # { version => audit entry } for the entries that created each version (rule.created for 1, rule.edited after,
  # each recording the version as [before, after]).
  def version_authors(entries)
    entries.each_with_object({}) do |entry, out|
      version = Array(entry.changeset["version"]).last
      out[version] ||= entry if version.is_a?(Integer)
    end
  end
end
