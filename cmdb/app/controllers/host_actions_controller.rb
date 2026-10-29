# Revoke, retire, and re-enroll (P1-D04, FR-1.1, FR-S.4). Each has a confirmation page (GET) and a
# CSRF-protected POST, so no destructive action is reachable by a simple link. Every action is audited by
# the Host transition methods, with the signed-in operator as actor.
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

  private

  def load_host
    @host = Host.find(params[:id])
    raise ActiveRecord::RecordNotFound if @host.retired? # nothing left to act on
  end
end
