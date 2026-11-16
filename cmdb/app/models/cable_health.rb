# Whether this process still delivers live updates (#194, review of #218). Solid Cable's listener is one thread per
# process, started when the first page subscribes. It retries only connection errors: any other error (a cancelled
# or failed poll) ends the thread for good, and from then on the process delivers no broadcast while every page's
# WebSocket stays open, so no page shows itself as stale. /health reports that as its live_updates check.
#
# It reads Solid Cable 4.1's listener thread, which is not public API: if the adapter changes shape, the check says
# so in the log and passes rather than failing every health check (spec/models/cable_health_spec.rb pins the shape).
module CableHealth
  module_function

  # False only when this process's Solid Cable listener was started and its thread has ended.
  def listening?(pubsub = ActionCable.server.pubsub)
    return true unless defined?(ActionCable::SubscriptionAdapter::SolidCable) && pubsub.is_a?(ActionCable::SubscriptionAdapter::SolidCable)

    listener = pubsub.instance_variable_get(:@listener)
    return true if listener.nil? # no page has subscribed in this process yet

    unless listener.respond_to?(:thread, true)
      Rails.logger.warn("[health] cannot see Solid Cable's listener thread; the live_updates check is skipped")
      return true
    end

    alive = listener.send(:thread)&.alive?
    Rails.logger.error("[health] Solid Cable's listener thread has stopped: this process delivers no live updates until it restarts") unless alive
    alive
  end
end
