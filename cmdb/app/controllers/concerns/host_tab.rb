# What every host tab shows above its content (P2-D02 to P2-D04, approved mockups): the host header with its
# notices, the summary tiles (HostSummary, owner decision Q1), and the tab bar. Retired hosts keep their pages.
module HostTab
  extend ActiveSupport::Concern

  private

  def load_host_tab
    @host = Host.includes(:inventory).find(params[:id])
    @credential = @host.agent_credentials.order(created_at: :desc, id: :desc).first
    @token = @host.enrollment_tokens.redeemable.order(created_at: :desc, id: :desc).first if @host.enrollment_state == "pending"
    @summary = HostSummary.new(@host)
  end

  # Whether the report that answered the latest request of this type recorded a snapshot (model: ConfigSnapshot or
  # PackageSnapshot), for the request box's "answered" hint. Not only the newest: a later report may have come since.
  def answered_with_snapshot?(availability, model)
    report_id = availability.latest&.satisfied_by_report_id
    report_id.present? && model.exists?(host_id: @host.id, report_id:)
  end
end
