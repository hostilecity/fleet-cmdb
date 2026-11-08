# A host's Packages tab and package snapshot comparison (P2-D03, FR-2.3, FR-2.5; approved mockups host-packages.html,
# host-packages-diff.html, states-packages-vulns.html). Read-only: the request button posts to
# HostActionsController#request_reports.
#
# - The current package set, one page of HostPackageList at a time (server-side search, filters, sort, pages of 50,
#   owner decision Q15), with the manager, the source package, and open findings per package; an unsupported
#   package manager is said so, never shown as an empty list.
# - Package snapshots, each with what changed since the one before it (PackageSnapshotTimeline, which caches it).
# - compare: any two snapshots, ?from=&to= (snapshot ids), on its own page as for config snapshots (Q5); by default
#   the latest against the one before it. A pair with an unsupported or unreadable side has no diff; a package named as skipped is
#   "Skipped / incomplete", never removed (P2-S08).
class HostPackagesController < ApplicationController
  include HostTab

  before_action :load_host_tab

  def show
    @set = HostPackageSet.find_by(host_id: @host.id)
    @availability = ReportRequests.availability(host: @host).fetch("packages")
    @answered_new_snapshot = answered_with_snapshot?(@availability, PackageSnapshot)
    @list = HostPackageList.new(@host.id, params.permit(:q, :arch, :findings, :sort, :dir, :page))
    @timeline = PackageSnapshotTimeline.new(@host.id)
    @last_readable = @timeline.last_readable if @set&.unreadable?
  end

  def compare
    timeline = PackageSnapshotTimeline.new(@host.id)
    @snapshot_count = timeline.count
    pair = timeline.pair(from: params[:from], to: params[:to])
    return unless pair

    @from, @to, @reversed, @pickable, @diff = pair.from, pair.to, pair.reversed, pair.pickable, pair.diff
    @kind = HostPackagesHelper::KIND_FILTERS.key?(params[:kind]) ? params[:kind] : nil
  end
end
