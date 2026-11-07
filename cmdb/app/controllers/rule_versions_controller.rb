# One version of a CIS-aligned rule, read-only (P2-D06, FR-2.2; approved mockup rule-version.html): its definition,
# what differs in the current version, who created it, when it was current, and whether any host's current result
# still uses it. Versions are never changed or deleted (CisRuleVersion), so there is nothing here to act on.
class RuleVersionsController < ApplicationController
  def show
    @rule = CisRule.includes(:current_version).find(params[:id])
    @version = @rule.versions.find_by!(version: params[:version])
    @current = @rule.current_version
    @next = @rule.versions.find_by(version: @version.version + 1)
    @author = AuditEntry.for_target(@rule).where(action: [ Audit::Actions::RULE_CREATED, Audit::Actions::RULE_EDITED ]).order(:occurred_at, :id)
                        .find { |entry| Array(entry.changeset["version"]).last == @version.version }
    @records = AuditLog::Records.for([ @author ].compact)
    @results_using = CisResult.joins(:host).merge(Host.in_fleet).where(cis_rule_version_id: @version.id).count
  end
end
