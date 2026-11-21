# The fleet compliance view (P2-D05, FR-2.5; approved mockup compliance.html, owner decisions Q8 to Q10): fleet-wide open
# CIS-aligned check failures and open vulnerability findings by severity, then every active host with its pass rate and
# its counts, filterable by search, tag, status, severity, and open findings with a fix (#256) and sortable, all in the URL, in keyset pages of 100 (#193).
# Read-only. FleetCompliance builds the page in a fixed number of queries whatever the fleet size.
class ComplianceController < ApplicationController
  reads_from_replica only: %i[index] # a caught-up replica when one is configured (#198)
  def index
    @compliance = FleetCompliance.new(params.permit(:q, :tag, :ecosystem, :status, :cis, :vuln, :fix, :sort, :after, :before))
    @totals = FleetCompliance.totals
    @rows = @totals.hosts.zero? ? [] : @compliance.rows
    @total = @compliance.filtered? ? @compliance.total : @totals.hosts
    @tags = FleetCompliance.tags
    @rules_defined = CisRule.exists?
    @advisory_freshness = Advisories::Freshness.statuses
  end
end
