# Coalesced live refreshes of open dashboard pages (#194). FleetBroadcast and TaskBroadcast name the Turbo streams a
# change affects and call request after it commits. A page that subscribes to a stream re-requests itself when the
# stream gets a Turbo page refresh, and morphs the result in (P1-D05, P3-DASH-TASKS).
#
# Each stream refreshes at most once per window (config.x.live_refresh.window, FLEET_LIVE_REFRESH_SECONDS, 2 s by
# default), however many changes it has, and never later than about one window after a change:
#
# - request writes each stream as a pending_refreshes row (a stream already pending is left as it is), then claims
#   the SCHEDULED marker row. Only the change that claims it enqueues a LiveRefreshJob, to run one window later, so
#   a burst of 1,000 changes is one job.
# - The job (flush) first deletes the marker, then deletes every pending stream and sends each one refresh. A change
#   that committed before the marker went is in that delete, so its pages see it; one after it claims the marker
#   again and schedules the next flush. The last change of a burst is never lost.
# - A marker older than the window plus ABANDONED_AFTER belongs to a job that was never enqueued or has died: the
#   next change takes it over and schedules a new flush.
# - When more than FAN_OUT_LIMIT streams of one group are pending at once (say a liveness run moved 5,000 hosts),
#   the group's shared stream gets one refresh in their place: every page of that group subscribes to it too.
#
# The rows are in the primary database, not the cache, so this needs no cache (the test environment has none) and
# adds no service. In the common case each change costs two small statements that take no row lock; the old
# design queued a Solid Queue job and sent a Solid Cable message per change.
#
# Solid Queue's concurrency controls do not fit: blocking keeps a row per change, and discarding loses the last one.
module LiveRefresh
  # The marker row's stream: present while a flush is scheduled. Turbo stream names here never start with "_".
  SCHEDULED = "_scheduled".freeze
  ABANDONED_AFTER = 1.minute
  DEFAULT_WINDOW = 2
  WINDOW_RANGE = (1..15)
  # Per-host streams sent one by one in one flush, at most; beyond it, their group's stream instead.
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
    streams = Array(streams).map(&:to_s).uniq
    return if streams.empty?

    PendingRefresh.insert_all(streams.map { |stream| { stream: } }) # ON CONFLICT DO NOTHING
    schedule if claim
  end

  # Sends one refresh to every pending stream (LiveRefreshJob) and returns the streams sent to. If a broadcast
  # fails, the streams not yet sent are requested again before the error is raised, so none is lost.
  def flush
    release
    streams = collapse(PendingRefresh.connection.select_values(
      PendingRefresh.sanitize_sql_array([ "DELETE FROM pending_refreshes WHERE stream <> ? RETURNING stream", SCHEDULED ])
    ).sort)
    streams.each_with_index do |stream, index|
      Turbo::StreamsChannel.broadcast_refresh_to(stream)
    rescue StandardError
      request(streams.drop(index))
      raise
    end
    streams
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
    release unless enqueued # the next change schedules it instead
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
