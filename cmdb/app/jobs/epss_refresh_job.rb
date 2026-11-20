# Refreshes FIRST's EPSS scores (VT-S03) from FLEET_EPSS_URL: SignalRefreshJob says how.
class EpssRefreshJob < SignalRefreshJob
  private

  def signal = Signals::EPSS
  def label = "FIRST EPSS download"
  def setting = "FLEET_EPSS_URL"

  def import(download, allowed_drops)
    Signals::EpssImport.new(origin: "feed", source: @source, operator: @operator, etag: download.etag, last_modified: download.last_modified, allowed_drops:)
                       .call(Signals::EpssReader.new(download.file.path, name: File.basename(@source)))
  end
end
