module AgentApi
  # Fixed-window request counters held in this process's memory (#191), for the agent API's hot limits: the
  # per-credential limit on authenticated endpoints and the per-address limit on failed authentication (S-5). They
  # cost no database write, unlike Rails.cache (Solid Cache), which did a row-locking upsert per request.
  #
  # Per process: with N Puma processes (WEB_CONCURRENCY), a client spread across them gets up to N times the limit.
  # That is enough to stop a runaway agent or a credential-guessing client; it is not a meter. A restart resets the
  # counters. Limits that must hold across processes need an edge limiter (docs/operations/configuration.md).
  #
  # Memory is bounded: at most max_keys windows. Keys are kept in least-recently-used order (a Ruby Hash keeps
  # insertion order, and a key is moved to the end when it is counted), windows that have ended are dropped from the
  # front as new counts arrive, and when the store is full the least recently counted key is dropped. A key that is
  # counted often, a flooding client, is therefore the last to be dropped. Dropping a key resets its count.
  #
  # Thread safe: one mutex, held for a few hash operations, never during I/O.
  #
  # It implements the store method Rails' rate_limit calls (increment), so limits_rate can use it.
  class RateLimiter
    Window = Struct.new(:count, :ends_at)

    attr_reader :max_keys

    def initialize(max_keys:)
      @max_keys = max_keys
      @windows = {}
      @mutex = Mutex.new
    end

    # Counts amount for key in its current window, which starts now when there is none and lasts expires_in.
    # Returns the count so far in that window.
    def increment(key, amount = 1, expires_in:)
      now = clock
      @mutex.synchronize do
        window = @windows.delete(key)
        window = Window.new(0, now + expires_in.to_f) if window.nil? || window.ends_at <= now
        window.count += amount
        @windows[key] = window
        drop_ended(now)
        @windows.shift while @windows.size > max_keys
        window.count
      end
    end

    # The count for key in its current window, without counting: 0 when it has none.
    def count(key)
      now = clock
      @mutex.synchronize do
        window = @windows[key]
        window && window.ends_at > now ? window.count : 0
      end
    end

    def size = @mutex.synchronize { @windows.size }

    def clear = @mutex.synchronize { @windows.clear }

    def clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    private

    # Windows at the front have gone longest without a count; drop those that have ended. A few per call at most
    # in steady state, so the cost per request stays constant.
    def drop_ended(now)
      while (first = @windows.first) && first.last.ends_at <= now
        @windows.delete(first.first)
      end
    end
  end
end
