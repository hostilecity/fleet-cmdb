# Dashboard and report pages read from a streaming replica of the primary when one is configured
# (REPLICA_DATABASE_URL, #198 step 2), to take their heavy reads off the primary that agents write to.
#
# A page reads the replica only once the replica has replayed everything the primary had written when the page
# started: the primary's WAL position (pg_current_wal_lsn) is read first, and the replica's replay position must reach
# it, waiting at most FLEET_REPLICA_MAX_WAIT_MS (100 ms by default). Otherwise the page reads the primary. So a page
# never shows older data than the primary would have shown at that moment: an operator's own change, a live refresh
# sent after a change committed, and an agent report all show at once. Commits need synchronous_commit on (the
# default) for this, so a commit is in the written WAL before it is acknowledged.
#
# A replica that cannot be reached (or that errors while a page reads it) is not tried again for BACKOFF, and pages
# read the primary meanwhile; the error is logged. A page that read the primary because the replica lagged logs
# "[replica] not caught up" at info level, so the share of such pages can be counted. Pages that write, need a second factor, or serve agents never come
# here: only the actions a controller names with reads_from_replica (ReplicaReads::Controller).
module ReplicaReads
  BACKOFF = 30.seconds
  POLL_INTERVAL = 0.005

  @mutex = Mutex.new
  @down_until = nil

  module_function

  # Whether this environment has a replica (ApplicationRecord's reading role).
  def configured? = ApplicationRecord.configurations.configs_for(env_name: Rails.env, name: "replica", include_hidden: true).present?

  def max_wait = Rails.configuration.x.replica_max_wait_ms / 1000.0

  # Runs the block on the replica when it has caught up, else on the primary. Returns the block's value.
  def around(&)
    return yield unless configured? && caught_up?

    begin
      ApplicationRecord.connected_to(role: :reading, prevent_writes: true, &)
    rescue ActiveRecord::ConnectionNotEstablished => e
      mark_down(e) if e.connection_pool&.role == :reading
      raise
    end
  end

  # Whether the replica has replayed the primary's current WAL position, waiting at most max_wait.
  def caught_up?
    return false if down?

    target = ApplicationRecord.connected_to(role: :writing) { ApplicationRecord.connection.select_value("SELECT pg_current_wal_lsn()::text", "Replica target") }
    check = ApplicationRecord.sanitize_sql_array([ "SELECT NOT pg_is_in_recovery() OR pg_last_wal_replay_lsn() >= ?::pg_lsn", target ])
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + max_wait
    ApplicationRecord.connected_to(role: :reading) do
      loop do
        return true if ApplicationRecord.connection.select_value(check, "Replica caught up")
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

  def down? = @mutex.synchronize { @down_until && Time.current < @down_until }

  def mark_down(error)
    @mutex.synchronize { @down_until = Time.current + BACKOFF }
    Rails.logger.error("[replica] #{error.class}: pages read the primary for #{BACKOFF.inspect}")
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

    # GET and HEAD only, whatever the routes say.
    def read_from_replica(&)
      return yield unless request.get? || request.head?

      ReplicaReads.around(&)
    end
  end
end
