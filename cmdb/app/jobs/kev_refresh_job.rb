# Refreshes CISA's Known Exploited Vulnerabilities catalog (VT-S02) from FLEET_KEV_URL: SignalRefreshJob says how.
class KevRefreshJob < SignalRefreshJob
  private

  def signal = Signals::KEV
  def label = "CISA KEV catalog"
  def setting = "FLEET_KEV_URL"

  def import(download, allowed_drops)
    Signals::KevImport.new(origin: "feed", source: @source, operator: @operator, etag: download.etag, last_modified: download.last_modified, allowed_drops:)
                      .call(Signals::KevReader.new(download.file.path, name: File.basename(@source)).read)
  end
end
