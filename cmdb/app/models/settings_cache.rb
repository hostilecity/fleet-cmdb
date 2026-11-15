# A per-process cache of the settings the agent API reads on every request (#189): the intervals a heartbeat sends
# (Setting.agent_intervals) and the poll hint a task poll sends (TaskSettings.poll_seconds). Each value is read at
# most once every TTL per process.
#
# A change through Setting (every settings write goes through it) clears this process's cache when it commits, so
# the dashboard's own process sends the new value at once. Other processes send it within TTL. Only values sent to
# agents as hints are cached here: limits that the server enforces (batch cap, output limit, expiry, liveness
# thresholds) are always read from the database.
#
# Thread safe: Puma threads share the cache. A value computed while a change commits is not stored, so a cleared
# cache never takes an older value back (the generation check).
module SettingsCache
  TTL = 10.seconds

  Entry = Data.define(:value, :expires_at)

  @entries = {}
  @generation = 0
  @mutex = Mutex.new

  module_function

  def fetch(name)
    now = clock
    generation = @mutex.synchronize do
      entry = @entries[name]
      return entry.value if entry && entry.expires_at > now

      @generation
    end
    value = yield
    @mutex.synchronize { @entries[name] = Entry.new(value:, expires_at: now + TTL.to_f) if @generation == generation }
    value
  end

  def clear
    @mutex.synchronize do
      @generation += 1
      @entries.clear
    end
  end

  def clock = Process.clock_gettime(Process::CLOCK_MONOTONIC)
end
