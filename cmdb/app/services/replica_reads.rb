# Dashboard and report pages read from a streaming replica of the primary when one is configured
# (REPLICA_DATABASE_URL, #198 step 2), to take their heavy reads off the primary that agents write to.
#
# A page reads the replica only once the replica has replayed everything the primary had written when the page
# started: the primary's WAL position (pg_current_wal_lsn) is read first, and the replica's replay position must reach
# it, waiting at most FLEET_REPLICA_MAX_WAIT_MS (100 ms by default). Otherwise the page reads the primary and logs
# "[replica] not caught up", so the share of such pages can be counted. So a page never shows older data than the
# primary would have shown at that moment: an operator's own change, a live refresh sent after a change committed, and
# an agent report all show at once. Commits need synchronous_commit on (the default) for this, so a commit is in the
# written WAL before it is acknowledged.
#
# A server that is not in recovery is never read as a replica (review of #237): a promoted ex-replica after a failover,
# or a URL naming the wrong server, has no replay position to compare and may hold different data. It is skipped like
# a failing one. Only the test environment, whose "replica" is the test database itself, allows it
# (config.x.replica_may_be_primary).
#
# A replica that cannot be reached, is not in recovery, or fails while a page reads it (a lost connection, or a query
# cancelled by a recovery conflict) is not tried again for FLEET_REPLICA_SKIP_SECONDS (30 by default); pages read the
# primary meanwhile, and the page that hit the failure is run again on the primary. An error from the primary is left
# alone: it never marks the replica down. Pages that write, need a second factor, or serve agents never come here:
# only the actions a controller names with reads_from_replica (ReplicaReads::Controller).
module ReplicaReads
  POLL_INTERVAL = 0.005
  # What a replica raises when it fails under a page: it is gone, the connection broke, or a recovery conflict
  # cancelled the query (SQLSTATE 40001).
  REPLICA_ERRORS = [ ActiveRecord::ConnectionNotEstablished, ActiveRecord::ConnectionFailed, ActiveRecord::SerializationFailure ].freeze

  @mutex = Mutex.new
  @down_until = nil

  module_function

  # Whether this environment has a replica (ApplicationRecord's reading role).
  def configured? = ApplicationRecord.configurations.configs_for(env_name: Rails.env, name: "replica", include_hidden: true).present?

  def max_wait = Rails.configuration.x.replica_max_wait_ms / 1000.0

  def skip_for = Rails.configuration.x.replica_skip_seconds.seconds

  # Runs the block on the replica when it has caught up, else on the primary, and returns its value. When the replica
  # fails while the block runs on it, the replica is skipped from then on and, if fallback is true (the caller has sent
  # nothing yet), the block runs once more on the primary; otherwise the error goes on.
  def around(fallback: true, &)
    return yield unless configured? && caught_up?

    begin
      ApplicationRecord.connected_to(role: :reading, prevent_writes: true, &)
    rescue *REPLICA_ERRORS, ActionView::Template::Error => e
      raise unless from_replica?(e)

      mark_down(e)
      raise unless fallback.respond_to?(:call) ? fallback.call : fallback

      yield
    end
  end

  # Whether the replica has replayed the primary's current WAL position, waiting at most max_wait. Reading the
  # primary's position is outside the rescue: an error there is the primary's, and goes on.
  def caught_up?
    return false if down?

    target = ApplicationRecord.connected_to(role: :writing) { ApplicationRecord.connection.select_value("SELECT pg_current_wal_lsn()::text", "Replica target") }
    replayed?(target)
  end

  def replayed?(target)
    check = ApplicationRecord.sanitize_sql_array([ "SELECT pg_is_in_recovery(), pg_last_wal_replay_lsn() >= ?::pg_lsn", target ])
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + max_wait
    ApplicationRecord.connected_to(role: :reading) do
      loop do
        recovering, reached = ApplicationRecord.connection.select_rows(check, "Replica caught up").first
        return not_a_replica unless recovering || Rails.configuration.x.replica_may_be_primary
        return true if reached || !recovering

        if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
          Rails.logger.info("[replica] not caught up within #{Rails.configuration.x.replica_max_wait_ms} ms; this page reads the primary")
          return false
        end
        sleep POLL_INTERVAL
      end
    end
  rescue ActiveRecord::ActiveRecordError => e
    mark_down(e)
    false
  end

  def not_a_replica
    mark_down(nil, "the replica server is not in recovery (promoted, or not a replica)")
    false
  end

  # Whether error (or, from a view, the error under it) came from the replica's pool.
  def from_replica?(error)
    error = error.cause if error.is_a?(ActionView::Template::Error)
    REPLICA_ERRORS.any? { |klass| error.is_a?(klass) } && error.connection_pool&.role == ActiveRecord.reading_role
  end

  def down? = @mutex.synchronize { @down_until && Time.current < @down_until }

  def mark_down(error, reason = nil)
    reason ||= "#{error.class}: #{error.message.lines.first.to_s.strip}"
    @mutex.synchronize { @down_until = Time.current + skip_for }
    Rails.logger.error("[replica] #{reason}; pages read the primary for #{skip_for.inspect}")
  end

  def reset! = @mutex.synchronize { @down_until = nil }

  # For dashboard controllers: reads_from_replica only: %i[index] wraps those actions, after every before_action the
  # controller inherits (signing in records the session's activity, a write), and with the view rendered inside.
  module Controller
    extend ActiveSupport::Concern

    class_methods do
      def reads_from_replica(only:)
        around_action :read_from_replica, only:
      end
    end

    private

    # GET and HEAD only, whatever the routes say. A page whose replica fails is run again on the primary, unless it has
    # already sent or rendered something.
    def read_from_replica(&)
      return yield unless request.get? || request.head?

      ReplicaReads.around(fallback: -> { !performed? }, &)
    end
  end
end
