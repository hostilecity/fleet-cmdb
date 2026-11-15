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
# - The job (flush) takes the pending rows by renaming them to "~<flush id>:<stream>" in one statement, sends each
#   stream one refresh outside any transaction, and then deletes the renamed rows. The marker stays held while it
#   sends, so changes meanwhile schedule nothing. Then the flush releases the marker, and if any stream became
#   pending meanwhile it claims the marker again and schedules the next flush. A change during the flush writes a
#   fresh row (the renamed one no longer has its name), so its pages get that next flush. The last change of a burst
#   is never lost.
# - If a broadcast fails, the renamed rows get their names back (unless a change has written that stream again) and
#   the flush raises with the marker still held, so the job's own retry is the only next flush (review of #212:
#   re-requesting and raising made each failure two new jobs). The cable database's statement and connect timeouts
#   (config/database.yml) bound a hung broadcast to about 2 s.
# - A marker older than the window plus ABANDONED_AFTER belongs to a job that was never enqueued, has died, or has
#   used up its retries: the next change, or LiveRefreshSweepJob within a minute, takes it over and schedules a new
#   flush. The sweep also gives back the names of rows a flush took and never finished (its worker died), and
#   schedules a flush for streams left pending with no marker.
# - Collapsing: when more than FAN_OUT_LIMIT streams of one group are pending at once, the group's shared stream gets
#   one refresh in their place (every page of that group subscribes to it too). FleetBroadcast applies the same
#   limit to one change, so a liveness run that moves 100,000 hosts writes two rows, not 100,001.
#
# Locks (follow-up to the review of #212). No transaction is held while broadcasting. A request's statements take no
# lock of their own on a committed row (INSERT ... ON CONFLICT DO NOTHING does not lock it, and the takeover check
# matches nothing unless the marker is old), but they do wait for a row that a flush is renaming or deleting at
# that moment, or a marker another request is inserting. A flush does each of those in one short statement. Each
# request statement also runs in its own short transaction with SET LOCAL lock_timeout (REQUEST_LOCK_TIMEOUT), so a
# change never waits longer than that whatever holds the row.
#
# The rows are in the primary database, not the cache, so this needs no cache (the test environment has none) and
# adds no service. Each change costs three small statements: the streams' insert, the marker's insert, and, when the
# marker is already held (the common case), the takeover check. The old design queued a Solid Queue job and sent a
# Solid Cable message per change.
#
# A failure to request (a lock timeout included) is reported (Rails.error) and logged, not raised: request runs
# after the change committed, so raising would fail an agent's request for work that is already saved. If the
# streams were written and only the marker's claim failed, the sweep schedules their flush within a minute; if the
# streams' insert itself timed out, those pages catch up at their next refresh.
#
# Solid Queue's concurrency controls do not fit: blocking keeps a row per change, and discarding loses the last one.
module LiveRefresh
  # The marker row's stream: present while a flush is scheduled or running. Turbo stream names never start with "_".
  SCHEDULED = "_scheduled".freeze
  # Rows a flush has taken start with this, the flush's id, and ":". Turbo stream names never start with "~".
  TAKEN = "~".freeze
  TAKEN_NAME = /\A~[0-9a-f]+:/
  ABANDONED_AFTER = 1.minute
  DEFAULT_WINDOW = 2
  WINDOW_RANGE = (1..15)
  # Per-host streams sent one by one in one flush, or requested by one change, at most; beyond it, their group's.
  FAN_OUT_LIMIT = 100
  # The longest a request's statement waits for a lock.
  REQUEST_LOCK_TIMEOUT = "500ms".freeze

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
  # The streams are committed before the marker is tried, so a flush that finds the marker held when this change
  # tried it also finds these streams when it looks for more.
  def request(streams)
    streams = Array(streams).map(&:to_s).uniq.sort
    return if streams.empty?

    briefly { PendingRefresh.insert_all(streams.map { |stream| { stream: } }) } # ON CONFLICT DO NOTHING, in key order
    schedule if briefly { claim }
  rescue StandardError => e
    Rails.error.report(e, handled: true, source: "live_refresh", context: { streams: streams.size })
    Rails.logger.error("[live_refresh] could not request a refresh of #{streams.size} streams: #{e.class.name}: #{e.message}")
  end

  # Sends one refresh to every pending stream (LiveRefreshJob) and returns the streams sent to. If a broadcast
  # fails, the streams are pending again, the marker is still held, and the error is raised for the job's retry.
  def flush
    prefix = "#{TAKEN}#{SecureRandom.hex(4)}:"
    streams = collapse(take(prefix))
    begin
      streams.each { |stream| Turbo::StreamsChannel.broadcast_refresh_to(stream) }
    rescue StandardError
      give_back(prefix)
      raise
    end
    taken(prefix).delete_all
    release
    schedule if pending.exists? && claim # streams a change wrote while this flush sent
    streams
  end

  # The every-minute check (LiveRefreshSweepJob): gives back the names of rows a flush took and never finished, then
  # schedules a flush for streams left pending with no marker, or behind a marker whose flush never came. Returns
  # whether it scheduled one.
  def sweep
    give_back(TAKEN, older_than: ABANDONED_AFTER)
    return false unless pending.exists? && claim

    schedule
    true
  end

  # Streams waiting for a flush: not the marker, and not taken by a flush.
  def pending = PendingRefresh.where.not(stream: SCHEDULED).where.not("stream LIKE ?", "#{TAKEN}%")

  def taken(prefix) = PendingRefresh.where("stream LIKE ?", "#{prefix}%")

  # Renames every pending stream to prefix + stream, in one statement, and returns the streams, sorted.
  def take(prefix)
    sql = PendingRefresh.sanitize_sql_array([ <<~SQL, prefix, SCHEDULED, "#{TAKEN}%" ])
      UPDATE pending_refreshes SET stream = ? || stream, requested_at = statement_timestamp()
      WHERE stream <> ? AND stream NOT LIKE ?
      RETURNING stream
    SQL
    PendingRefresh.with_connection { |connection| connection.select_values(sql) }.map { |name| name.delete_prefix(prefix) }.sort
  end

  # Gives the rows taken with this prefix their names back, in one short transaction; a stream a change has written
  # again since keeps the change's row. With older_than, only rows taken that long ago: a flush that died.
  def give_back(prefix, older_than: nil)
    rows = taken(prefix)
    rows = rows.where("requested_at < statement_timestamp() - make_interval(secs => ?)", older_than.to_i) if older_than
    PendingRefresh.transaction do
      names = rows.pluck(:stream)
      next if names.empty?

      PendingRefresh.insert_all(names.map { |name| name.sub(TAKEN_NAME, "") }.uniq.sort.map { |stream| { stream: } })
      PendingRefresh.where(stream: names).delete_all
    end
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

  # The block in its own short transaction, waiting at most REQUEST_LOCK_TIMEOUT for any lock.
  def briefly
    # with_connection, not .connection: that would lease the connection to this thread for good, so a thread that
    # borrowed one (with_connection) would never give it back to the pool.
    PendingRefresh.with_connection do |connection|
      connection.transaction(requires_new: true) do
        connection.execute("SET LOCAL lock_timeout = '#{REQUEST_LOCK_TIMEOUT}'")
        yield
      end
    end
  end

  # Groups: a prefix and the stream every page of the group also subscribes to.
  def collapse(streams)
    FleetBroadcast::GROUPS.reduce(streams) do |list, (prefix, shared)|
      members, rest = list.partition { |stream| stream.start_with?(prefix) }
      members.size > FAN_OUT_LIMIT ? (rest | [ shared ]).sort : list
    end
  end
end
