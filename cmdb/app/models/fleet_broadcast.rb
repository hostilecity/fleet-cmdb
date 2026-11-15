# Live fleet updates (P1-D05). Code that changes what the fleet pages or a host's pages show calls hosts_changed
# inside its transaction; the refresh is requested only after the outermost transaction commits, so browsers never
# see uncommitted state, and not at all if it rolls back. Each open page then re-requests itself with its own query
# parameters and morphs the result in, so filter membership, sort order, counts, empty states, new and retired
# hosts, and the host header all stay right together, with nothing rendered in the message (review of #53).
# LiveRefresh coalesces the refreshes: each stream at most once per window (#194).
#
# Streams:
# - STREAM: the fleet list and the fleet-wide summaries (compliance, releases and rollouts, approvals). Every change.
# - host_stream(id): every page of one host (its tabs, and its task pages through TaskBroadcast). Its changes only,
#   so an open host page does not refresh when another host changes.
# - ALL_HOSTS_STREAM: every host page too, for changes that are not one host's (refresh), and in place of many host
#   streams at once (LiveRefresh::FAN_OUT_LIMIT).
module FleetBroadcast
  STREAM = "fleet".freeze
  HOST_PREFIX = "fleet:host:".freeze
  ALL_HOSTS_STREAM = "fleet:all-hosts".freeze
  GROUPS = { HOST_PREFIX => ALL_HOSTS_STREAM }.freeze

  module_function

  def host_stream(host_id) = "#{HOST_PREFIX}#{host_id}"

  def hosts_changed(host_ids)
    ids = Array(host_ids).compact.uniq
    return if ids.empty?

    # More hosts than one flush would send one by one: every host page refreshes instead, and one row is written in
    # place of a row per host (review of #212: 100,000 rows for a fleet-wide liveness change).
    streams = ids.size > LiveRefresh::FAN_OUT_LIMIT ? [ ALL_HOSTS_STREAM ] : ids.map { |id| host_stream(id) }
    ActiveRecord.after_all_transactions_commit { LiveRefresh.request([ STREAM, *streams ]) }
  end

  # Something every open fleet page may show changed without one host changing: an onboarding request arrived or
  # was decided (P1-D07), so the "waiting for approval" notice and list refresh; an advisory import may have changed
  # severities the compliance counts are grouped by (P2-D05); a rollout changed. CIS evaluation and vulnerability
  # matching call hosts_changed once per run, with the hosts whose shown compliance changed.
  def refresh
    ActiveRecord.after_all_transactions_commit { LiveRefresh.request([ STREAM, ALL_HOSTS_STREAM ]) }
  end
end
