# A host's Packages tab and package snapshot comparison (P2-D03, FR-2.3, FR-2.5; approved mockups host-packages.html,
# host-packages-diff.html, states-packages-vulns.html). Read-only: the request button posts to
# HostActionsController#request_reports.
#
# - The current package set, one page of HostPackageList at a time (server-side search, filters, sort, pages of 50,
#   owner decision Q15), with the manager, the source package, and open findings per package; an unsupported
#   package manager is said so, never shown as an empty list.
# - Package snapshots, each with what changed since the one before it (PackageDiff).
# - compare: any two snapshots, ?from=&to= (snapshot ids), on its own page as for config snapshots (Q5); by default
#   the latest against the one before it. A pair with an unsupported or unreadable side has no diff; a package named as skipped is
#   "Skipped / incomplete", never removed (P2-S08).
class HostPackagesController < ApplicationController
  include HostTab

  SNAPSHOT_LIMIT = 10
  KINDS = %w[installed removed upgraded downgraded invalid skipped equivalent].freeze

  before_action :load_host_tab

  def show
    @set = HostPackageSet.find_by(host_id: @host.id)
    @availability = ReportRequests.availability(host: @host).fetch("packages")
    @list = HostPackageList.new(@host.id, params.permit(:q, :arch, :findings, :sort, :dir, :page))
    rows = PackageSnapshot.where(host_id: @host.id).order(received_at: :desc, id: :desc).limit(SNAPSHOT_LIMIT + 1).to_a
    @latest_snapshot = rows.first
    @last_readable = PackageSnapshot.where(host_id: @host.id).where.not(manager: "unreadable").order(received_at: :desc, id: :desc).first if @set&.unreadable?
    @more_snapshots = rows.size > SNAPSHOT_LIMIT
    @snapshots = rows.first(SNAPSHOT_LIMIT).each_with_index.map do |snapshot, i|
      previous = rows[i + 1]
      known = rows[(i + 1)..].find { |row| !row.unreadable? } # an unreadable report says nothing changed (P2-S08)
      { snapshot:, previous:, first: previous.nil? && !@more_snapshots, diff: (PackageDiff.between(known, snapshot) if known) }
    end
  end

  def compare
    snapshots = PackageSnapshot.where(host_id: @host.id).order(received_at: :desc, id: :desc).select(:id, :received_at, :manager, :package_count).to_a
    @snapshot_count = snapshots.size
    named = params.values_at(:from, :to).select(&:present?) # a named snapshot must be this host's, even with nothing to compare
    raise ActiveRecord::RecordNotFound, "no such package snapshot for this host" unless named.all? { |id| snapshots.any? { |s| s.id.to_s == id } }
    return if snapshots.size < 2

    @to = params[:to].present? ? snapshots.find { |s| s.id.to_s == params[:to] } : snapshots.first
    @from = params[:from].present? ? snapshots.find { |s| s.id.to_s == params[:from] } : snapshots[snapshots.index(@to).to_i + 1]
    raise ActiveRecord::RecordNotFound, "no such package snapshot for this host" unless @from && @to

    @reversed = ([ @from.received_at, @from.id ] <=> [ @to.received_at, @to.id ]).positive?
    @pickable = snapshots.map { |s| [ s, s == snapshots.first, s == snapshots.last ] } # every snapshot kept, as for config snapshots
    loaded = PackageSnapshot.where(id: [ @from.id, @to.id ]).index_by(&:id)
    @diff = PackageDiff.between(loaded.fetch(@from.id), loaded.fetch(@to.id))
    @kind = KINDS.include?(params[:kind]) ? params[:kind] : nil
  end
end
