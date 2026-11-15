# Tells signed-in dashboards that the fleet changed (P1-D05). The message is a Turbo page refresh: each open
# fleet list or host page re-requests itself with its own query parameters and morphs the result in. So
# filter membership, sort order, counts, empty states, new and retired hosts, and the host header all stay
# right together, with nothing rendered here (review of #53). Turbo debounces bursts of refreshes.
class FleetBroadcastJob < ApplicationJob
  # Open pages refresh within seconds, never behind a long import (S-7, config/queue.yml). After the every-minute
  # jobs on the same queue (a larger number runs later), so a burst of changes cannot hold them up. A burst still
  # queues one refresh per change; coalescing them is #194.
  queue_as :realtime
  queue_with_priority ApplicationJob::BROADCAST_PRIORITY

  # host_ids are the hosts that changed; they are logged for tracing. Every page on the stream refreshes.
  def perform(host_ids = [])
    logger.info("[fleet_broadcast] refresh for hosts #{Array(host_ids).join(',')}")
    Turbo::StreamsChannel.broadcast_refresh_to(FleetBroadcast::STREAM)
  end
end
