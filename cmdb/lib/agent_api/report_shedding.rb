module AgentApi
  # Report load shedding (#200). The signal is simple and per process: report requests in flight (POST
  # /api/v1/reports/inventory, config, and packages). When FLEET_REPORT_MAX_IN_FLIGHT are already being handled,
  # another report is answered at once with 503 overloaded and a Retry-After of FLEET_REPORT_RETRY_AFTER_SECONDS to
  # 1.5 times that, chosen at random so a fleet turned away together does not come back together. The agent keeps the
  # report (same report_id) and waits that long; it honours at most 15 minutes (agent/src/retry.rs,
  # RetryPolicy::reports), which is 1.5 times the setting's bound of 600 (review of #208).
  # Heartbeats, task calls, and everything else are never shed. 0, the default, turns shedding off.
  #
  # Applied by Api::V1::AuthenticatedController (sheds_report_load) after the failed-authentication check and before
  # authentication and the request transaction (review of #208): an address the failed-authentication limit refuses
  # never takes a slot, and a shed request costs no database work.
  module ReportShedding
    # Reports in flight in this process. One per process, shared by its threads.
    class Gauge
      def initialize
        @lock = Mutex.new
        @count = 0
      end

      def count = @lock.synchronize { @count }

      # Takes a slot unless limit are taken; returns whether it did.
      def enter(limit)
        @lock.synchronize do
          return false if @count >= limit

          @count += 1
          true
        end
      end

      def leave = @lock.synchronize { @count -= 1 }
    end

    GAUGE = Gauge.new

    module_function

    def settings = AgentApi.config.report_shedding

    # Runs the block with a slot taken, or returns the Retry-After seconds when every slot is taken.
    def within_limit(gauge: GAUGE, random: Random)
      limit = settings[:max_in_flight]
      return [ true, yield ] unless limit.positive?

      base = settings[:retry_after]
      return [ false, base + random.rand(0..(base / 2)) ] unless gauge.enter(limit)

      begin
        [ true, yield ]
      ensure
        gauge.leave
      end
    end
  end
end
