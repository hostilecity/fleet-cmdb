# Helpers for specs of live refreshes (#194, LiveRefresh).
module LiveRefreshHelpers
  # The streams waiting for the next flush, sorted.
  def pending_refreshes = PendingRefresh.where.not(stream: LiveRefresh::SCHEDULED).pluck(:stream).sort

  # The host ids among the pending streams.
  def pending_host_refreshes = host_ids(pending_refreshes)

  def host_ids(streams)
    streams.filter_map { |stream| Integer(stream.delete_prefix(FleetBroadcast::HOST_PREFIX)) if stream.start_with?(FleetBroadcast::HOST_PREFIX) }
  end

  def clear_pending_refreshes = PendingRefresh.delete_all

  # Records each LiveRefresh.request call's streams in refresh_requests, and still makes it.
  def record_refresh_requests
    @refresh_requests = []
    allow(LiveRefresh).to receive(:request).and_wrap_original do |original, streams|
      @refresh_requests << Array(streams)
      original.call(streams)
    end
  end

  attr_reader :refresh_requests

  # Each request that refreshed the fleet stream, as the host ids it named.
  def fleet_refresh_requests = refresh_requests.select { |streams| streams.include?(FleetBroadcast::STREAM) }.map { |streams| host_ids(streams) }

  # The streams a page listens to, from its signed <turbo-cable-stream-source> names.
  def page_streams(page)
    page.css("turbo-cable-stream-source").map { |source| Turbo::StreamsChannel.verified_stream_name(source["signed-stream-name"]) }
  end
end

RSpec.configure do |config|
  config.include LiveRefreshHelpers
  # Specs without a transaction (the concurrency specs) commit their refresh requests. A marker left behind would
  # hold back the next example's flush for a minute, so every example ends with none.
  config.after { PendingRefresh.delete_all }
end
