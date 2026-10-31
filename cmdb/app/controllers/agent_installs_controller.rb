# "Install an agent" (P1-D08, FR-S.5, NFR-4; mockup agents-install.html): the exact commands to download a
# release from the agent hostname, check its SHA-256, and run the installer. Every value in the commands
# comes from the one release shown, so a copied command never mixes releases.
class AgentInstallsController < ApplicationController
  def show
    @release = if params[:version].present?
      AgentRelease.find_by(version: params[:version].to_s) or raise ActiveRecord::RecordNotFound
    else
      AgentRelease.current
    end
  end
end
