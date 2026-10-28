# Tells signed-in dashboards that the fleet changed (P1-D05). The message is a Turbo page refresh: each open
# fleet list or host page re-requests itself with its own query parameters and morphs the result in. So
# filter membership, sort order, counts, empty states, new and retired hosts, and the host header all stay
# right together, with nothing rendered here (review of #53). Turbo debounces bursts of refreshes.
class FleetBroadcastJob < ApplicationJob
  queue_as :default

  # host_ids are the hosts that changed; they are logged for tracing. Every page on the stream refreshes.
  def perform(host_ids = [])
    logger.info("[fleet_broadcast] refresh for hosts #{Array(host_ids).join(',')}")
    Turbo::StreamsChannel.broadcast_refresh_to(FleetBroadcast::STREAM)
  end
end
