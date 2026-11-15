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
  # insertion order, and a key is moved to the end when it is counted, or read with touch: true), windows that have
  # ended are dropped from the front as new counts arrive, and when the store is full the least recently used key is
  # dropped. Dropping a key resets its count. A key that keeps being counted or checked is therefore the last to go:
  # a flooding client, and a blocked address that keeps trying (the failed-authentication limit reads it with touch:
  # true, review of #211), stay counted. About 260 bytes a key in RSS (100,000 keys, about 26 MB).
  #
  # remember and live? keep a sliding expiry instead of a count: AgentApi.recent_credentials uses them to know which
  # key ids authenticated recently.
  #
  # Thread safe: one mutex, held for a few hash operations, never during I/O. Every read and write of the hash is
  # under it (spec/lib/agent_api/rate_limiter_spec.rb forces a thread switch inside the critical section).
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

    # The count for key in its current window, without counting: 0 when it has none. touch: true also moves the key
    # to the most recently used end, so a key that is checked often is not the first dropped.
    def count(key, touch: false)
      now = clock
      @mutex.synchronize do
        window = @windows[key]
        next 0 unless window && window.ends_at > now

        @windows[key] = @windows.delete(key) if touch
        window.count
      end
    end

    # Marks key as seen now, for expires_in from now (sliding: every call pushes the expiry back).
    def remember(key, expires_in:)
      now = clock
      @mutex.synchronize do
        @windows.delete(key)
        @windows[key] = Window.new(1, now + expires_in.to_f)
        drop_ended(now)
        @windows.shift while @windows.size > max_keys
      end
      nil
    end

    # Whether key was remembered (or counted) and has not expired.
    def live?(key) = count(key).positive?

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
