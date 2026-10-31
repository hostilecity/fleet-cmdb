# The Agents page's releases (P1-RELEASES, P1-D06 mockup agents.html): imported releases, imports from GitHub,
# and uploads for networks without internet access. Every import and refusal is audited with the signed-in
# operator as actor. Rollouts join this page with P1-UPDATES.
class AgentReleasesController < ApplicationController
  # The three uploaded files, with room for the multipart framing. Checked before the body is parsed.
  MAX_UPLOAD_BYTES = Releases::MAX_BINARY_BYTES + Releases::MAX_MANIFEST_BYTES + Releases::MAX_SIGNATURE_BYTES + 64.kilobytes
  # "0.3.0", "v0.3.0", or the tag "agent-v0.3.0".
  TAG_PREFIX = /\A(?:agent-)?v/

  # Before sign-in and CSRF checks, which would parse the multipart body.
  prepend_before_action :limit_upload_size, only: :upload

  def index
    load_page
  end

  # POST /agents/releases/import: queue an import from GitHub.
  def import
    @version = params[:version].to_s.strip
    version = @version.sub(TAG_PREFIX, "")
    return refuse_form(:import, "Enter a version such as 1.2.0, without build metadata.") unless Releases.valid_version?(version)
    return refuse_form(:import, "#{version} is already imported.") if AgentRelease.exists?(version:)

    AgentReleaseImport.close_stale!(version)
    return refuse_form(:import, "#{version} is already being imported.") if AgentReleaseImport.in_flight.exists?(version:)

    import = AgentReleaseImport.transaction(requires_new: true) do
      AgentReleaseImport.create!(version:, operator: current_operator, request_id: request.request_id)
    end
    AgentReleaseImportJob.perform_later(import.id)
    redirect_to agents_path, notice: "Importing #{version} from GitHub. The result appears under Imports."
  rescue ActiveRecord::RecordNotUnique
    refuse_form(:import, "#{version} is already being imported.")
  end

  # POST /agents/releases/upload: the binary, manifest, and signature as files, verified while the operator
  # waits.
  def upload
    files = %i[manifest signature binary].index_with { |name| params[name] }
    unless files.values.all? { |file| file.is_a?(ActionDispatch::Http::UploadedFile) }
      return refuse_form(:upload, "Choose all three files: the binary, its .manifest.json, and its .manifest.json.minisig.")
    end

    manifest = files[:manifest].read(Releases::MAX_MANIFEST_BYTES + 1)
    signature = files[:signature].read(Releases::MAX_SIGNATURE_BYTES + 1)
    result = Releases::Import.new(operator: current_operator, source: "upload")
      .call(manifest: manifest.to_s, signature: signature.to_s) { files[:binary].tap(&:rewind) }
    FleetBroadcast.refresh
    notice = result.created ? "Imported #{result.release.version}. Signature and checksum verified." : "#{result.release.version} was already imported."
    redirect_to agents_path, notice:
  rescue Releases::Refused => e
    Releases::Import.record_refusal(operator: current_operator, source: "upload", version: nil, reason: e.message)
    refuse_form(:upload, "Refused: #{e.message}.")
  end

  private

  # Puma buffers a chunked body and then sets its length, and refuses one over http_content_length_limit
  # (config/puma.rb) before Rails sees it. Behind any other server, a body without a length is refused here
  # rather than parsed. The header is read as sent: Request#content_length turns a missing one into 0, and
  # reads the whole body to measure a chunked one (review of #74).
  def limit_upload_size
    length = request.get_header("CONTENT_LENGTH").to_s
    return render(plain: "The upload needs a Content-Length.", status: :length_required) unless length.match?(/\A\d+\z/)
    return if length.to_i <= MAX_UPLOAD_BYTES

    render plain: "The upload is larger than an agent release can be (#{Releases::MAX_BINARY_BYTES / 1.megabyte} MiB).", status: :content_too_large
  end

  def load_page
    @releases = AgentRelease.includes(:imported_by).newest_first
    @running = Host.in_fleet.where(agent_version: @releases.map(&:version)).group(:agent_version).count
    @imports = AgentReleaseImport.includes(:operator).recent.to_a
    @keys = Releases.keys
  end

  def refuse_form(form, message, status: :unprocessable_content)
    @errors = { form => message }
    load_page
    render :index, status:
  end
end
