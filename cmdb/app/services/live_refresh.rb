# Coalesced live refreshes of open dashboard pages (#194). FleetBroadcast and TaskBroadcast name the Turbo streams a
# change affects and call request after it commits. A page that subscribes to a stream re-requests itself when the
# stream gets a Turbo page refresh, and morphs the result in (P1-D05, P3-DASH-TASKS).
#
# Each stream refreshes at most once per window (config.x.live_refresh.window, FLEET_LIVE_REFRESH_SECONDS, 2 s by
# default), however many changes it has, and never later than about one window after a change:
#
# - request writes each stream as a pending_refreshes row (a stream already pending is left as it is), then claims
#   the SCHEDULED marker row. Only the change that claims it enqueues a LiveRefreshJob, to run one window later, so
#   a burst of 1,000 changes is one job. Streams are written in sorted order, so two requests that overlap take the
#   same rows in the same order and cannot deadlock (review of #212).
# - The job (flush) runs one transaction: it deletes the marker, then deletes every pending stream, then sends each
#   one refresh. A change whose rows committed before the delete is in it, so its pages see it. A change during the
#   flush waits on the marker row (and on any stream row being deleted) until the flush commits, then claims the
#   marker again and schedules the next flush. The last change of a burst is never lost.
# - If a broadcast fails, or the worker dies mid-flush, the transaction rolls back: the streams are pending again and
#   the marker is held again, so the job's own retry is the only next flush, and changes meanwhile schedule nothing
#   more (review of #212: re-requesting and raising made each failure two new jobs).
# - A marker older than the window plus ABANDONED_AFTER belongs to a job that was never enqueued, has died, or has
#   used up its retries: the next change, or LiveRefreshSweepJob within a minute, takes it over and schedules a new
#   flush. The sweep also schedules one for streams left pending with no marker.
# - Collapsing: when more than FAN_OUT_LIMIT streams of one group are pending at once, the group's shared stream gets
#   one refresh in their place (every page of that group subscribes to it too). FleetBroadcast applies the same
#   limit to one change, so a liveness run that moves 100,000 hosts writes two rows, not 100,001.
#
# The rows are in the primary database, not the cache, so this needs no cache (the test environment has none) and
# adds no service. Each change costs three small statements that take no row lock: the streams' insert, the marker's
# insert, and, when the marker is already held, a takeover check that matches nothing unless the marker is old. The
# old design queued a Solid Queue job and sent a Solid Cable message per change.
#
# A failure to request is reported (Rails.error) and logged, not raised: request runs after the change committed, so
# raising would fail an agent's request for work that is already saved. The pages catch up at the next refresh.
#
# Solid Queue's concurrency controls do not fit: blocking keeps a row per change, and discarding loses the last one.
module LiveRefresh
  # The marker row's stream: present while a flush is scheduled. Turbo stream names here never start with "_".
  SCHEDULED = "_scheduled".freeze
  ABANDONED_AFTER = 1.minute
  DEFAULT_WINDOW = 2
  WINDOW_RANGE = (1..15)
  # Per-host streams sent one by one in one flush, or requested by one change, at most; beyond it, their group's.
  FAN_OUT_LIMIT = 100

  module_function

  def window = Rails.configuration.x.live_refresh.window

  # FLEET_LIVE_REFRESH_SECONDS as a duration: a whole number of seconds in WINDOW_RANGE, DEFAULT_WINDOW when unset.
  def parse_window(value)
    value = value.presence || DEFAULT_WINDOW.to_s
    seconds = Integer(value, 10, exception: false)
    unless seconds && WINDOW_RANGE.cover?(seconds)
      raise ArgumentError, "FLEET_LIVE_REFRESH_SECONDS must be a whole number of seconds from #{WINDOW_RANGE.min} to #{WINDOW_RANGE.max} (got #{value.inspect})"
    end

    seconds.seconds
  end

  # Refreshes the open pages on these streams within about one window. Call it after the change has committed.
  def request(streams)
    streams = Array(streams).map(&:to_s).uniq.sort
    return if streams.empty?

    PendingRefresh.insert_all(streams.map { |stream| { stream: } }) # ON CONFLICT DO NOTHING, in key order
    schedule if claim
  rescue StandardError => e
    Rails.error.report(e, handled: true, source: "live_refresh", context: { streams: streams.size })
    Rails.logger.error("[live_refresh] could not request a refresh of #{streams.size} streams: #{e.class.name}: #{e.message}")
  end

  # Sends one refresh to every pending stream (LiveRefreshJob) and returns the streams sent to. One transaction, the
  # marker's delete first: if a broadcast fails, or the process dies, the streams stay pending and the marker held,
  # and the error is raised for the job's retry. Solid Cable writes to its own database, so they are not held back.
  def flush
    PendingRefresh.transaction do
      release
      streams = collapse(PendingRefresh.connection.select_values(
        PendingRefresh.sanitize_sql_array([ "DELETE FROM pending_refreshes WHERE stream <> ? RETURNING stream", SCHEDULED ])
      ).sort)
      streams.each { |stream| Turbo::StreamsChannel.broadcast_refresh_to(stream) }
      streams
    end
  end

  # LiveRefreshJob's every-minute check (LiveRefreshSweepJob): schedules a flush for streams left pending with no
  # marker, or behind a marker whose flush never came. Returns whether it scheduled one.
  def sweep
    return false unless PendingRefresh.where.not(stream: SCHEDULED).exists? && claim

    schedule
    true
  end

  # Whether this change takes the marker: a new one, or one abandoned by a flush that never ran.
  def claim
    return true if PendingRefresh.insert_all([ { stream: SCHEDULED } ], returning: [ :stream ]).rows.any?

    PendingRefresh.where(stream: SCHEDULED)
                  .where("requested_at < statement_timestamp() - make_interval(secs => ?)", (window + ABANDONED_AFTER).to_i)
                  .update_all("requested_at = statement_timestamp()") == 1
  end

  def schedule
    enqueued = false
    enqueued = LiveRefreshJob.set(wait: window).perform_later
  ensure
    release unless enqueued # the next change, or the sweep, schedules it instead
  end

  def release = PendingRefresh.where(stream: SCHEDULED).delete_all

  # Groups: a prefix and the stream every page of the group also subscribes to.
  def collapse(streams)
    FleetBroadcast::GROUPS.reduce(streams) do |list, (prefix, shared)|
      members, rest = list.partition { |stream| stream.start_with?(prefix) }
      members.size > FAN_OUT_LIMIT ? (rest | [ shared ]).sort : list
    end
  end
end
