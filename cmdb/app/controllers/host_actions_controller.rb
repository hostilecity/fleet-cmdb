# Revoke, retire, and re-enroll (P1-D04, FR-1.1, FR-S.4). Each has a confirmation page (GET) and a
# CSRF-protected POST, so no destructive action is reachable by a simple link. Every action is audited by
# the Host transition methods, with the signed-in operator as actor.
#
# Requesting fresh reports (P2-S03, the host page button of P2-D02) changes nothing on the VM but what the agent
# reports next, so it is a CSRF-protected POST with no confirmation page. ReportRequests audits and rate limits it.
class HostActionsController < ApplicationController
  include ShowsEnrollmentToken

  before_action :load_host

  def confirm_revoke; end

  def revoke
    @host.revoke!(actor: current_operator)
    redirect_to host_path(@host), notice: "Credential revoked. The agent is refused from its next request."
  rescue Host::InvalidTransition
    redirect_to host_path(@host), alert: "Only an active host's credential can be revoked."
  end

  def confirm_retire; end

  # Retiring cannot be undone, so the operator types the hostname to confirm (approved mockups, P1-D06).
  def retire
    unless params[:confirm_hostname].to_s.strip.downcase == @host.hostname
      @confirm_error = "Type #{@host.hostname} exactly to retire this host."
      return render :confirm_retire, status: :unprocessable_content
    end

    @host.retire!(actor: current_operator)
    redirect_to root_path, notice: "#{@host.name} retired. Its history and audit entries are kept."
  end

  def confirm_reenroll; end

  # The unattended way to re-enroll: a new one-time token. The interactive way needs nothing here: the
  # operator runs the installer with --reenroll and approves the request (P1-D07).
  def reenroll
    token = Enrollment::IssueToken.call(host: @host, actor: current_operator)
    show_token(token, created: false)
  end

  def request_reports
    types = params.permit(report_types: []).fetch(:report_types, [])
    result = ReportRequests.request!(host: @host, types:, actor: current_operator)
    redirect_to host_path(@host, anchor: "report_requests"), **report_request_flash(result)
  rescue ReportRequests::NoTypes
    redirect_to host_path(@host, anchor: "report_requests"), alert: "Choose at least one report to request."
  rescue ReportRequests::NotActive
    redirect_to host_path(@host), alert: "Only an active host's agent can be asked for a report."
  end

  private

  # A notice for what was requested; an alert when everything asked for was rate limited.
  def report_request_flash(result)
    names = ->(types) { helpers.report_names(types).upcase_first }
    parts = []
    parts << "#{names.(result.requested)} requested. The agent is asked on its next heartbeat." if result.requested.any?
    parts << "#{names.(result.outstanding)} already requested, waiting for the agent." if result.outstanding.any?
    if result.rate_limited.any?
      parts << "#{names.(result.rate_limited)} requested less than #{ReportRequests::COOLDOWN.in_minutes.to_i} minutes ago. " \
               "Try again after #{result.retry_at.utc.strftime('%H:%M:%S')} UTC."
    end
    { (result.requested.empty? && result.rate_limited.any? ? :alert : :notice) => parts.join(" ") }
  end

  def load_host
    @host = Host.in_fleet.find(params[:id]) # a retired host has nothing left to act on
  end
end
