# The Advisory data sources page (P2-D06, FR-2.4; approved mockups data-sources.html, data-sources-stale.html,
# data-sources-import.html, and the refresh and full import confirmations in dialogs.html): where vulnerability
# data comes from and how fresh it is, "Refresh now" with its cool-down (P2-S15), and uploading an advisory
# file (P2-S10). Every change is audited with the signed-in operator as actor, by Advisories::ManualRefresh,
# this controller (the upload), and Advisories::Import (its outcome).
#
# An upload is imported in the background (owner decision on #129): the file, at most MAX_UPLOAD_BYTES (the
# server's request body limit, config/puma.rb), is stored with its queued import in one transaction
# (AdvisoryUpload), AdvisoryUploadImportJob imports it, and the result page refreshes itself until it is done.
# At most AdvisoryUpload::MAX_PENDING uploads are stored at once. A larger archive is imported with
# bin/rails advisories:import.
class DataSourcesController < ApplicationController
  MAX_UPLOAD_BYTES = AdvisoryUpload::MAX_BYTES
  # How often the result page of an import in progress refreshes itself.
  PROGRESS_REFRESH_SECONDS = 2
  PENDING_LOCK_KEY = "advisories.upload".freeze
  # The multipart framing and the form's other fields around the file.
  MAX_BODY_BYTES = MAX_UPLOAD_BYTES + 64.kilobytes
  EXTENSIONS = %w[.json .zip].freeze
  NOT_CONFIGURED = "No advisory feed is configured on the server (FLEET_ADVISORY_FEED_URL), so there is nothing to refresh. Upload a file instead.".freeze

  # Before sign-in and CSRF checks, which would parse the multipart body.
  prepend_before_action :limit_upload_size, only: :upload

  def show
    load_page
  end

  # GET /data-sources/refresh: the confirmation. While the cool-down runs the page's button is disabled, so this
  # only sends the operator back to it.
  def confirm_refresh
    sources = AdvisoryDataSources.new
    return redirect_to(data_sources_path, alert: NOT_CONFIGURED) unless sources.feed_configured?
    return redirect_to(data_sources_path(anchor: "feed")) if sources.refresh_allowed_at

    @source = sources.feed.source
  end

  # POST /data-sources/refresh. The server decides: a second refresh within the cool-down is refused here, with
  # the time it is next allowed, even if the page that sent it was drawn before the first.
  def refresh
    result = Advisories::ManualRefresh.request!(actor: current_operator)
    if result.accepted?
      redirect_to data_sources_path(anchor: "feed"),
                  notice: "Refresh started. The download and import can take several minutes; the result appears under Recent imports."
    else
      redirect_to data_sources_path(anchor: "feed"),
                  alert: "Refresh refused: a refresh started less than #{helpers.cooldown_words} ago. " \
                         "It is available again at #{helpers.utc_clock(result.next_allowed_at)}."
    end
  rescue Advisories::ManualRefresh::NotConfigured
    redirect_to data_sources_path, alert: NOT_CONFIGURED
  end

  # POST /data-sources/upload: store an OSV .json file or a .zip archive of them, queue its import, and show its
  # progress.
  def upload
    file = params[:advisory_file]
    return refuse("Choose an advisory file to upload.") unless file.is_a?(ActionDispatch::Http::UploadedFile)

    @name = upload_name(file)
    return refuse("Upload an OSV .json file or a .zip archive of them.") unless EXTENSIONS.include?(File.extname(@name).downcase)
    return refuse("The file is larger than #{MAX_UPLOAD_BYTES / 1.megabyte} MiB. Import a larger archive on the server with bin/rails advisories:import.") if file.size > MAX_UPLOAD_BYTES

    @full = params[:full] == "1"
    # A full import can mark advisories withdrawn and so resolve findings: it needs the confirmation's own button.
    return refuse("Confirm the full import, or clear Full import to import without withdrawing.", field: :full) if @full && params[:confirm_full] != "1"

    import = store_upload(file)
    return refuse("#{AdvisoryUpload::MAX_PENDING} uploads are already waiting to be imported. Wait for one to finish, then upload again.") unless import

    AdvisoryUploadImportJob.perform_later(import.id)
    redirect_to advisory_import_path(import)
  end

  # GET /data-sources/imports/:id: what one import did (data-sources-import.html).
  def import
    @import = AdvisoryImport.includes(:operator).find(params[:id])
  end

  private

  def load_page
    @sources = AdvisoryDataSources.new
    @statuses = @sources.statuses
    @ecosystems = @sources.ecosystems
    @feed = @sources.feed
    @refresh_at = @sources.refresh_allowed_at
    @last_attempt = @sources.last_attempt
    @imports = @sources.imports
    @failed_refreshes = @sources.failed_refreshes
  end

  def refuse(message, field: :advisory_file)
    @upload_error = { field => message }
    load_page
    render :show, status: :unprocessable_content
  end

  # The file's own name, without a client's path, as the import stores and shows it (never trusted as a path).
  def upload_name(file)
    name = file.original_filename.to_s.dup.force_encoding(Encoding::UTF_8).scrub("?").tr("\\", "/").split("/").last
    Advisories::Record.clean_text(name, 200) || "upload"
  end

  # The queued import and its stored file, in one transaction, audited; nil when MAX_PENDING uploads are stored
  # already. The count is taken under a lock, so uploads sent together cannot pass it.
  def store_upload(file)
    AdvisoryImport.transaction do
      AdvisoryImport.connection.execute("SELECT pg_advisory_xact_lock(hashtext(#{AdvisoryImport.connection.quote(PENDING_LOCK_KEY)}))")
      next nil if AdvisoryUpload.count >= AdvisoryUpload::MAX_PENDING

      now = Time.current
      import = AdvisoryImport.create!(origin: "file", source: @name, full: @full, operator: current_operator, state: "queued", started_at: now)
      AdvisoryUpload.create!(advisory_import: import, operator: current_operator, filename: @name, byte_size: file.size,
                             data: File.binread(file.path), created_at: now, expires_at: now + AdvisoryUpload::LIFETIME)
      Audit.record(actor: current_operator, action: Audit::Actions::ADVISORY_UPLOADED, target: import,
                   changes: { "source" => @name, "full" => @full, "bytes" => file.size })
      import
    end
  end

  # As on the Agents page's upload (AgentReleasesController): a body without a length, or longer than the limit,
  # is refused before it is parsed.
  def limit_upload_size
    length = request.get_header("CONTENT_LENGTH").to_s
    return render(plain: "The upload needs a Content-Length.", status: :length_required) unless length.match?(/\A\d+\z/)
    return if length.to_i <= MAX_BODY_BYTES

    render plain: "The upload is larger than #{MAX_UPLOAD_BYTES / 1.megabyte} MiB. Import a larger archive on the server with bin/rails advisories:import.",
           status: :content_too_large
  end
end
