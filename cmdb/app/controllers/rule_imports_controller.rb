# Importing a rules file from the dashboard (P2-D06, FR-2.2; approved mockups rules-import.html, rules-import-preview.html,
# rules-import-errors.html; owner decision Q13).
#
# - create: the uploaded file is checked as a whole by the import's own checks (CisRules::ImportPlan, which uses
#   RuleFile.parse). A file with any problem lists every problem with its JSON Pointer and stores nothing. A valid
#   file is kept as a RuleImportPreview (15 minutes, one per operator, in the database) and its preview shown: the
#   rules it would add, change, enable or disable, leave unchanged, and the stored rules it does not list. Nothing
#   is written to the rules.
# - apply: imports exactly the stored file (CisRules::Import, the rake task's import, with the operator as actor)
#   with the choice made at upload, and only if the rules are still as they were when it was previewed: Import
#   checks CisRule.state_digest under the rules' write lock. If they changed, nothing is applied and the same file
#   is previewed again against the rules as they are now, saying why, so the operator confirms what will really
#   happen. Applying or cancelling drops the stored file.
class RuleImportsController < ApplicationController
  # The rules file and the form's other fields, with room for the multipart framing. Checked before the body is parsed.
  MAX_UPLOAD_BYTES = CisRules::RuleFile::MAX_BYTES + 64.kilobytes

  prepend_before_action :limit_upload_size, only: :create
  before_action :load_preview, only: %i[show apply destroy]

  def new; end

  def create
    file = params[:file]
    return refuse("Choose a YAML or JSON rules file to check.") unless file.is_a?(ActionDispatch::Http::UploadedFile)

    @filename = RuleImportPreview.display_filename(file.original_filename)
    # One byte past the limit, so an oversized file is refused without reading it all (as rules:import does).
    body = (file.read(CisRules::RuleFile::MAX_BYTES + 1) || "").force_encoding(Encoding::UTF_8)
    disable_missing = params[:disable_missing] == "1"
    result = CisRules::ImportPlan.call(body, disable_missing:)
    unless result.ok?
      @problems = result.errors
      return render(:errors, status: :unprocessable_content)
    end

    preview = RuleImportPreview.store!(operator: current_operator, filename: @filename, body:, disable_missing:, rules_digest: result.plan.state_digest)
    redirect_to import_preview_rules_path(preview.token)
  end

  def show
    @plan = plan_for(@preview)
  end

  def apply
    result = CisRules::Import.call(@preview.body, actor: current_operator, disable_missing: @preview.disable_missing,
                                   expected_state: @preview.rules_digest, source: "file_upload")
    unless result.ok? # the checks changed under the file (a new fact manifest), so it is refused as a new upload would be
      @filename = @preview.filename
      @problems = result.errors.map { |text| CisRules::RuleFile::Problem.new(pointer: text.split(": ", 2).first, message: text.split(": ", 2).last) }
      @preview.destroy!
      return render(:errors, status: :unprocessable_content)
    end

    @preview.destroy!
    redirect_to rules_path, notice: applied_notice(result)
  rescue CisRules::Import::Stale
    @plan = plan_for(@preview)
    @preview.restart!(rules_digest: @plan.state_digest)
    @restarted = true
    render :show, status: :conflict
  end

  def destroy
    @preview.destroy!
    redirect_to import_rules_path, notice: "Import cancelled. The uploaded file was discarded; nothing was imported."
  end

  private

  def load_preview
    @preview = RuleImportPreview.for_operator(current_operator, params[:token])
    return if @preview

    redirect_to import_rules_path, alert: "That preview has expired, was already applied or cancelled, or was replaced by a later upload. Nothing was imported. Upload the file again."
  end

  # The plan for a stored file, which passed every check when it was stored.
  def plan_for(preview) = CisRules::ImportPlan.call(preview.body, disable_missing: preview.disable_missing).plan

  # Puma refuses a body over http_content_length_limit before Rails sees it; behind any other server, a body without
  # a length, or one too large to be a rules file, is refused here rather than parsed (as agent release uploads).
  def limit_upload_size
    length = request.get_header("CONTENT_LENGTH").to_s
    return render(plain: "The upload needs a Content-Length.", status: :length_required) unless length.match?(/\A\d+\z/)
    return if length.to_i <= MAX_UPLOAD_BYTES

    render plain: "The upload is larger than a rules file can be (#{CisRules::RuleFile::MAX_BYTES / 1.megabyte} MiB).", status: :content_too_large
  end

  def refuse(message)
    @error = message
    render :new, status: :unprocessable_content
  end

  def applied_notice(result)
    # Import counts a rule whose only change is its flag as unchanged too; the preview does not, and nor does this.
    unchanged = result.unchanged - result.enabled - result.disabled
    parts = { "added" => result.created, "changed" => result.versioned, "enabled" => result.enabled, "disabled" => result.disabled, "unchanged" => unchanged }
    summary = parts.map { |word, keys| "#{keys.size} #{word}" }.to_sentence
    "Imported #{@preview.filename}: #{summary}.#{' Every host is checked against the added and changed rules now; no agent is contacted.' if result.changed?}"
  end
end
