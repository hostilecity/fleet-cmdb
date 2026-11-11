# Settings: Tasks (P3-S06, mockup settings-tasks.html, owner decisions Q31 to Q33): the restart allowlist, the
# protected services (fixed, shown only), and the task limits. Every change needs a recent second factor
# (change_task_settings), checked on the server for every request, and TaskSettings validates and audits it. Errors
# are shown in place with what was typed (FR-S.4); a refused code shows the page again with the code box saying why.
class TaskSettingsController < ApplicationController
  # The entry first, so a refused code can show the removal again; a removal of an entry already gone changes nothing.
  before_action :load_entry, only: %i[confirm_remove remove_service]
  require_second_factor "change_task_settings", only: %i[add_service remove_service update_limits]

  def show
    load_page
  end

  def add_service
    @service = params[:service].to_s
    @tag = params[:tag].to_s
    entry = TaskSettings.add_service!(service: @service, tag: @tag, actor: current_operator)
    redirect_to task_settings_path(anchor: "allowlist"), notice: "Added #{entry.service} for #{entry.tag ? "hosts tagged #{entry.tag}" : 'every host'}. Recorded in the audit log. Each VM must list it too before a restart runs there."
  rescue TaskSettings::Invalid => e
    @service_errors = e.errors
    render_page(:unprocessable_content)
  end

  def confirm_remove
    @refused = TaskSettings.tasks_refused_without(@entry)
  end

  def remove_service
    TaskSettings.remove_service!(@entry.id, actor: current_operator)
    redirect_to task_settings_path(anchor: "allowlist"), notice: "Removed #{@entry.service} (#{@entry.tag ? "hosts tagged #{@entry.tag}" : 'every host'}). Recorded in the audit log. Queued restarts it covered are refused when their agent picks them up."
  end

  def update_limits
    @limit_values = limit_params
    changes = TaskSettings.update_limits!(@limit_values, actor: current_operator)
    notice = if changes.empty? then "Nothing changed."
    else "Limits saved. #{changes.map { |key, (before, after)| "#{AuditEntriesHelper::TASK_LIMIT_NAMES.fetch(key)}: #{before} → #{after}" }.join('; ')}. Recorded in the audit log. Applies from now on; tasks already queued keep their expiry."
    end
    redirect_to task_settings_path(anchor: "limits"), notice:
  rescue TaskSettings::Invalid => e
    @limit_errors = e.errors
    render_page(:unprocessable_content)
  end

  private

  def load_entry
    @entry = TaskAllowedService.find_by(id: params[:id])
    redirect_to task_settings_path(anchor: "allowlist"), alert: "That service is no longer on the list." unless @entry
  end

  def load_page
    @allowlist = TaskSettings.allowlist
    @limits = TaskSettings.limits
    @tags = Host.in_fleet.distinct.pluck(Arel.sql("unnest(tags)")).sort
  end

  def render_page(status)
    load_page
    render :show, status:
  end

  # Only the known fields; expiry by catalog type.
  def limit_params
    values = params.permit(*TaskSettings::LIMITS.keys, expiry_hours: TaskCatalog.current.types).to_h
    values["expiry_hours"] = values["expiry_hours"].to_h if values.key?("expiry_hours")
    values
  end

  # A refused code: the same page again, with what was typed and the code box saying why, under the form it came from.
  def second_factor_refused(result)
    response.headers["Cache-Control"] = "no-store"
    status = result.status == :locked ? :too_many_requests : :forbidden
    case action_name
    when "remove_service"
      @refused = TaskSettings.tasks_refused_without(@entry)
      render :confirm_remove, status:
    else
      @refused_form = action_name
      @service = params[:service].to_s
      @tag = params[:tag].to_s
      @limit_values = limit_params if action_name == "update_limits"
      render_page(status)
    end
  end
end
