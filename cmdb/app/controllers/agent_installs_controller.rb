# "Install an agent" (P1-D08, FR-S.5, NFR-4; mockup agents-install.html): the exact commands to download a
# release from the agent hostname, check its signature with the release public key from the repository on GitHub
# (#181), and run the installer. Every value in the commands comes from the one release shown, so a copied command
# never mixes releases.
class AgentInstallsController < ApplicationController
  def show
    @release = if params[:version].present?
      AgentRelease.find_by(version: params[:version].to_s) or raise ActiveRecord::RecordNotFound
    else
      AgentRelease.current
    end
    return unless @release

    # The key the release was signed with, and which of the repository's keys it is, if any. The command on the VM
    # trusts only the repository's key at the release's tag; these let the page say whether that will pass.
    repository = Releases.repository_keys
    @signing_key = Releases.keys.find { |key| key.id_hex == @release.key_id }
    @repository_role = repository.compact.find { |_role, key| key.line == @signing_key&.line }&.first
    @keys_unlike_repository = Releases.keys_unlike_repository
  end
end
