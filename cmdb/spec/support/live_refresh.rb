# Helpers for specs of live refreshes (#194, LiveRefresh).
module LiveRefreshHelpers
  # The last example run, to name in the marker guard.
  mattr_accessor :last_example

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

  # A committed marker left behind would silently hold back every later example's flush for a minute (review of
  # #212). Specs without a transaction (the concurrency specs) are the only ones that commit refresh rows:
  # - After one, a marker still held with no flush queued is a leak, and fails the example. The rows are then
  #   deleted, so the next example starts clean either way.
  # - Before any example, a committed marker fails it, naming the example that left it, in case one ever escapes.
  config.before do
    leaked = PendingRefresh.exists?(stream: LiveRefresh::SCHEDULED)
    raise "a committed live-refresh marker was left by #{LiveRefreshHelpers.last_example || 'an earlier example'}" if leaked
  end

  config.after do |example|
    LiveRefreshHelpers.last_example = example.full_description
    next if self.class.use_transactional_tests

    held = PendingRefresh.exists?(stream: LiveRefresh::SCHEDULED)
    queued = ActiveJob::Base.queue_adapter.enqueued_jobs.any? { |job| job["job_class"] == "LiveRefreshJob" }
    PendingRefresh.delete_all
    raise "the live-refresh marker is held with no flush queued: it leaked" if held && !queued
  end
end
