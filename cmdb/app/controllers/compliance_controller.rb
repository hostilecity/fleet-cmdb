# The fleet compliance view (P2-D05, FR-2.5; approved mockup compliance.html, owner decisions Q8 to Q10): fleet-wide open
# CIS-aligned check failures and open vulnerability findings by severity, then every active host with its pass rate and
# its counts, filterable by search, tag, status, and severity and sortable, all in the URL. Read-only. FleetCompliance
# builds the page in a fixed number of queries whatever the fleet size.
class ComplianceController < ApplicationController
  def index
    @compliance = FleetCompliance.new(params.permit(:q, :tag, :ecosystem, :status, :cis, :vuln, :sort, :page))
    @totals = FleetCompliance.totals
    @rows = @totals.hosts.zero? ? [] : @compliance.rows
    @tags = FleetCompliance.tags
    @rules_defined = CisRule.exists?
    @advisory_freshness = Advisories::Freshness.statuses
  end
end
