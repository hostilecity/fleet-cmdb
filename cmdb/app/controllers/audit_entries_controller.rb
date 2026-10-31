# The fleet-wide audit log (FR-S.3, P1-AUDIT-PAGE): read-only, behind sign-in like every dashboard page
# (FR-S.4). Filters and the page position are query parameters (AuditLog), so any view can be bookmarked.
# There is no create, update, or destroy action, and nothing here writes.
class AuditEntriesController < ApplicationController
  def index
    # Read from the query string itself: Rails reserves params[:action] for the routed action ("index"),
    # and the filter is called action, as in Audit::Actions. Only plain strings are filter values.
    query = request.query_parameters.slice(*AuditLog::PARAMS.map(&:to_s)).select { |_, value| value.is_a?(String) }
    # The filter form sends every field; the address keeps only the ones in use, so it stays short and
    # readable when bookmarked or shared.
    return redirect_to(helpers.audit_page_path(query.reject { |_, value| value.blank? })) if query.any? { |_, value| value.blank? }

    @log = AuditLog.new(query.with_indifferent_access)
    @page = @log.page
    @records = AuditLog::Records.for(@page.entries)
    render status: (@log.valid? ? :ok : :unprocessable_content)
  end
end
