# The fleet list and host detail pages (FR-1.5, P1-D02, P1-D03). Read-only here; operator actions arrive
# with P1-DASH-ACTIONS.
class HostsController < ApplicationController
  HISTORY_LIMIT = 25
  STATUS_HISTORY_LIMIT = 20
  AUDIT_LIMIT = 20

  def index
    @fleet = FleetList.new(params.permit(:q, :tag, :status, :sort, :dir))
    @hosts = @fleet.hosts.to_a
    @counts = FleetList.counts
    @tags = FleetList.tags
  end

  def show
    @host = Host.includes(:inventory).find(params[:id]) # retired hosts keep their page and history
    @inventory = @host.inventory
    @credential = @host.agent_credentials.order(created_at: :desc).first
    @token = @host.enrollment_tokens.redeemable.order(created_at: :desc).first if @host.enrollment_state == "pending"
    @history = history
    @status_events = @host.status_events.order(occurred_at: :desc, id: :desc).limit(STATUS_HISTORY_LIMIT)
    @audit_entries = AuditEntry.for_target(@host).order(occurred_at: :desc, id: :desc).limit(AUDIT_LIMIT).to_a
    @actors = audit_actors(@audit_entries)
  end

  private

  # Newest first, each with the changes from the snapshot before it.
  def history
    snapshots = @host.inventory_snapshots.order(received_at: :desc, id: :desc).limit(HISTORY_LIMIT + 1).to_a
    snapshots.first(HISTORY_LIMIT).each_with_index.map do |snapshot, i|
      previous = snapshots[i + 1]
      { snapshot:, first: previous.nil? && snapshots.size <= HISTORY_LIMIT, changes: previous ? InventoryDiff.between(previous.stable, snapshot.stable) : [] }
    end
  end

  # Display names for audit actors, loaded in two queries.
  def audit_actors(entries)
    operators = Operator.where(id: entries.select { |e| e.actor_type == "operator" }.map(&:actor_id)).index_by(&:id)
    hosts = Host.where(id: entries.select { |e| e.actor_type == "host" }.map(&:actor_id)).index_by(&:id)
    entries.to_h do |e|
      name = case e.actor_type
      when "operator" then operators[e.actor_id]&.display_name || "A former operator"
      when "host" then hosts[e.actor_id] ? "the host" : "a host"
      else "the system"
      end
      [ e.id, name ]
    end
  end
end
