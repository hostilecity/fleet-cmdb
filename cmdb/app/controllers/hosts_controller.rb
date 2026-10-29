# The fleet list and host detail pages (FR-1.5, P1-D02, P1-D03), pre-registration and editing (P1-D04).
# Revoke, retire, and re-enroll are in HostActionsController.
class HostsController < ApplicationController
  include ShowsEnrollmentToken

  FIELDS = %i[name hostname tags description notes].freeze
  HISTORY_LIMIT = 25
  STATUS_HISTORY_LIMIT = 20
  AUDIT_LIMIT = 20

  def index
    @fleet = FleetList.new(params.permit(:q, :tag, :status, :sort, :dir))
    @hosts = @fleet.hosts.to_a
    @counts = FleetList.counts
    @tags = FleetList.tags
    @awaiting_approval = OnboardingRequest.awaiting.count
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

  # Pre-register a host for an unattended install (P1-D04, DEC-17): the host is created pending with a
  # one-time token, shown once on the response to this POST and never again.
  def new
    @host = Host.new
  end

  def create
    @host, token = Enrollment::RegisterHost.call(host_params, actor: current_operator)
    show_token(token, created: true)
  rescue ActiveRecord::RecordInvalid => e
    @host = e.record
    render :new, status: :unprocessable_content
  end

  def edit
    @host = editable_host
  end

  def update
    @host = editable_host
    @host.edit!(host_params, actor: current_operator)
    redirect_to host_path(@host), notice: "Changes saved."
  rescue ActiveRecord::RecordInvalid
    render :edit, status: :unprocessable_content
  end

  private

  def host_params = params.expect(host: FIELDS)

  def editable_host
    host = Host.find(params[:id])
    raise ActiveRecord::RecordNotFound if host.retired? # retired hosts are kept as they were

    host
  end

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
