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
end
