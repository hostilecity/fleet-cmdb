# The Advisory data sources page (P2-D06, FR-2.4; approved mockups data-sources.html, data-sources-stale.html,
# data-sources-import.html, and the refresh and full import confirmations in dialogs.html): where vulnerability
# data comes from and how fresh it is, "Refresh now" with its cool-down (P2-S15), and uploading an advisory
# file (P2-S10). Every change is audited with the signed-in operator as actor, by Advisories::ManualRefresh and
# Advisories::Import.
#
# An upload is imported while the operator waits, as an agent release upload is verified (P1-RELEASES), rather
# than by a job: the file then never has to be stored where a worker can read it. The upload is at most
# MAX_UPLOAD_BYTES, the server's request body limit (config/puma.rb), which imports in well under a minute (about
# 2,000 records a second in testing). A larger archive is imported with bin/rails advisories:import. If a proxy
# in front of the server gives up first, the import still finishes and appears under Recent imports.
class DataSourcesController < ApplicationController
  MAX_UPLOAD_BYTES = 64.megabytes
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

  # POST /data-sources/upload: import an OSV .json file or a .zip archive of them, then show the result.
  def upload
    file = params[:advisory_file]
    return refuse("Choose an advisory file to upload.") unless file.is_a?(ActionDispatch::Http::UploadedFile)

    @name = upload_name(file)
    return refuse("Upload an OSV .json file or a .zip archive of them.") unless EXTENSIONS.include?(File.extname(@name).downcase)
    return refuse("The file is larger than #{MAX_UPLOAD_BYTES / 1.megabyte} MiB. Import a larger archive on the server with bin/rails advisories:import.") if file.size > MAX_UPLOAD_BYTES

    @full = params[:full] == "1"
    # A full import can mark advisories withdrawn and so resolve findings: it needs the confirmation's own button.
    return refuse("Confirm the full import, or clear Full import to import without withdrawing.", field: :full) if @full && params[:confirm_full] != "1"

    result = Advisories::Import.new(origin: "file", source: @name, full: @full, operator: current_operator)
                               .call(Advisories::Reader.new(file.path, name: @name))
    # Kept for the result page that follows, once: re-matching runs in a job and the import does not store it.
    session[:advisory_matching] = matching(result)
    redirect_to advisory_import_path(result.import)
  rescue Advisories::Unreadable => e
    import = Advisories::Import.record_failure(origin: "file", source: @name, reason: e.message, operator: current_operator, full: @full)
    redirect_to advisory_import_path(import)
  end

  # GET /data-sources/imports/:id: what one import did (data-sources-import.html).
  def import
    @import = AdvisoryImport.includes(:operator).find(params[:id])
    matching = session.delete(:advisory_matching)
    @matching = matching if matching.is_a?(Hash) && matching["import_id"] == @import.id
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

  # What the import result page says about re-matching: how many changed source packages, on how many hosts.
  def matching(result)
    sources = result.changed_packages.values.flatten.uniq
    hosts = sources.empty? ? 0 : HostPackage.joins(:host).merge(Host.in_fleet).where("COALESCE(host_packages.source, host_packages.name) IN (?)", sources).distinct.count(:host_id)
    { "import_id" => result.import.id, "packages" => sources.size, "hosts" => hosts }
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
