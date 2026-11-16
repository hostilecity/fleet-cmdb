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
# - The job (flush), in one short transaction, stamps the marker as its own and takes the pending rows by renaming
#   them to "~<flush id>:<stream>", both with that transaction's time. Then it sends each stream one refresh, with no
#   transaction open, and deletes the renamed rows. The marker stays held while it sends, so changes meanwhile
#   schedule nothing. Then the flush releases the marker, only if it still carries its own stamp, and if any stream
#   became pending meanwhile it claims the marker again and schedules the next flush. A change during the flush
#   writes a fresh row (the renamed one no longer has its name), so its pages get that next flush. The last change
#   of a burst is never lost.
# - Sending is fire-and-forget. Solid Cable's broadcast only queues the message in memory, and its writer thread
#   reports (Rails.error) and drops a batch it cannot write. So a cable fault does not fail the flush, and that
#   refresh is lost; the pages catch up at their next one (review of #218; the owner decides whether that needs more).
#   What can fail a flush is the primary database, or another adapter that raises: then the renamed rows get their
#   names back (unless a change has written that stream again) and the flush raises with the marker still held, so
#   the job's retry is the only next flush (review of #212: re-requesting and raising made each failure two new jobs).
#   LiveRefreshJob retries within about 20 s, inside the marker's takeover age, so one failure is one retry chain.
# - A marker older than the window plus ABANDONED_AFTER belongs to a flush that was never enqueued, has died, is
#   stalled, or has used up its retries: the next change, or LiveRefreshSweepJob within a minute, takes it over (a
#   new stamp) and schedules a new flush. The sweep gives back the names of taken rows only when the flush that took
#   them no longer owns a live marker (review of #218), so a slow but running flush keeps its rows; if it was only
#   stalled, it sends them again later, which is harmless. It also schedules a flush for streams left pending with
#   no marker.
# - Collapsing: when more than FAN_OUT_LIMIT streams of one group are pending at once, the group's shared stream gets
#   one refresh in their place (every page of that group subscribes to it too). FleetBroadcast applies the same
#   limit to one change, so a liveness run that moves 100,000 hosts writes two rows, not 100,001.
#
# Locks (review of #212). No transaction is held while sending. A request's statements take no
# lock of their own on a committed row (INSERT ... ON CONFLICT DO NOTHING does not lock it, and the takeover check
# matches nothing unless the marker is old), but they do wait for a row that a flush is renaming or deleting at
# that moment, or a marker another request is inserting. A flush does each of those in one short statement or
# transaction. Each
# request statement also runs in its own short transaction with SET LOCAL lock_timeout (REQUEST_LOCK_TIMEOUT), so
# a change never waits longer than that whatever holds the row.
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
  # Rows a flush has taken start with this, eight hex digits of the flush's id, and ":". Stream names never start
  # with "~".
  TAKEN = "~".freeze
  TAKEN_NAME = /\A~[0-9a-f]{8}:/
  # The stream column holds 128 characters, and a taken name adds 10 ("~" + 8 + ":"). A longer name would make every
  # flush's rename fail, so request refuses it (review of #218). Today's longest is "fleet:host:<id>", 30 at most.
  MAX_STREAM_LENGTH = 118
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

    too_long = streams.find { |stream| stream.length > MAX_STREAM_LENGTH }
    raise ArgumentError, "live-refresh stream names are at most #{MAX_STREAM_LENGTH} characters: #{too_long.first(40)}..." if too_long

    briefly { PendingRefresh.insert_all(streams.map { |stream| { stream: } }) } # ON CONFLICT DO NOTHING, in key order
    stamp = briefly { claim }
    schedule(stamp) if stamp
  rescue StandardError => e
    Rails.error.report(e, handled: true, source: "live_refresh", context: { streams: streams.size })
    Rails.logger.error("[live_refresh] could not request a refresh of #{streams.size} streams: #{e.class.name}: #{e.message}")
  end

  # Sends one refresh to every pending stream (LiveRefreshJob) and returns the streams sent to. If the flush fails
  # before it is done, the streams are pending again, the marker is still held, and the error is raised for the
  # job's retry.
  def flush
    prefix = "#{TAKEN}#{SecureRandom.hex(4)}:"
    stamp, names = own_and_take(prefix)
    streams = collapse(names)
    begin
      streams.each { |stream| Turbo::StreamsChannel.broadcast_refresh_to(stream) }
    rescue StandardError
      give_back(taken(prefix))
      raise
    end
    taken(prefix).delete_all
    release(stamp)
    next_stamp = pending.exists? && claim # streams a change wrote while this flush sent
    schedule(next_stamp) if next_stamp
    streams
  end

  # The every-minute check (LiveRefreshSweepJob): gives back the names of rows taken by a flush that no longer owns
  # a live marker, then schedules a flush for streams left pending with no marker, or behind a marker whose flush
  # never came. Returns whether it scheduled one.
  def sweep
    give_back(taken(TAKEN).where(<<~SQL.squish, SCHEDULED, (window + ABANDONED_AFTER).to_i))
      NOT EXISTS (SELECT 1 FROM pending_refreshes marker WHERE marker.stream = ?
                  AND marker.requested_at = pending_refreshes.requested_at
                  AND marker.requested_at >= statement_timestamp() - make_interval(secs => ?))
    SQL
    stamp = pending.exists? && claim
    return false unless stamp

    schedule(stamp)
    true
  end

  # Streams waiting for a flush: not the marker, and not taken by a flush.
  def pending = PendingRefresh.where.not(stream: SCHEDULED).where.not("stream LIKE ?", "#{TAKEN}%")

  def taken(prefix) = PendingRefresh.where("stream LIKE ?", "#{prefix}%")

  # In one short transaction: stamps the marker with this transaction's time (taking it over from any other flush),
  # and renames every pending stream to prefix + stream with the same time. Returns the stamp and the streams, sorted.
  def own_and_take(prefix)
    stamp_sql = PendingRefresh.sanitize_sql_array([ <<~SQL.squish, SCHEDULED ])
      INSERT INTO pending_refreshes (stream, requested_at) VALUES (?, now())
      ON CONFLICT (stream) DO UPDATE SET requested_at = now() RETURNING requested_at
    SQL
    take_sql = PendingRefresh.sanitize_sql_array([ <<~SQL.squish, prefix, SCHEDULED, "#{TAKEN}%" ])
      UPDATE pending_refreshes SET stream = ? || stream, requested_at = now()
      WHERE stream <> ? AND stream NOT LIKE ? RETURNING stream
    SQL
    PendingRefresh.with_connection do |connection|
      connection.transaction(requires_new: true) do
        [ connection.select_value(stamp_sql), connection.select_values(take_sql).map { |name| name.delete_prefix(prefix) }.sort ]
      end
    end
  end

  # Gives these taken rows their names back, in one short transaction; a stream a change has written again since
  # keeps the change's row.
  def give_back(rows)
    PendingRefresh.transaction do
      names = rows.pluck(:stream)
      next if names.empty?

      PendingRefresh.insert_all(names.map { |name| name.sub(TAKEN_NAME, "") }.uniq.sort.map { |stream| { stream: } })
      PendingRefresh.where(stream: names).delete_all
    end
  end

  # The marker's new stamp if this change takes it (a new one, or one abandoned), or nil when it is held.
  def claim
    insert = PendingRefresh.sanitize_sql_array([ "INSERT INTO pending_refreshes (stream) VALUES (?) ON CONFLICT DO NOTHING RETURNING requested_at", SCHEDULED ])
    takeover = PendingRefresh.sanitize_sql_array([ <<~SQL.squish, SCHEDULED, (window + ABANDONED_AFTER).to_i ])
      UPDATE pending_refreshes SET requested_at = statement_timestamp()
      WHERE stream = ? AND requested_at < statement_timestamp() - make_interval(secs => ?) RETURNING requested_at
    SQL
    PendingRefresh.with_connection { |connection| connection.select_value(insert) || connection.select_value(takeover) }
  end

  def schedule(stamp)
    enqueued = false
    enqueued = LiveRefreshJob.set(wait: window).perform_later
  ensure
    release(stamp) unless enqueued # the next change, or the sweep, schedules it instead
  end

  # Deletes the marker only if it still carries this stamp: a flush or change that took it over owns it now.
  def release(stamp) = PendingRefresh.where(stream: SCHEDULED).where("requested_at = ?::timestamp", stamp).delete_all

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
