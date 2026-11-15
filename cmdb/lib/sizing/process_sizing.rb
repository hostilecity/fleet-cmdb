# How many threads and processes the server runs, and so how many database connections each process may open
# (#198, S-7, docs/operations/scaling.md). One place for config/puma.rb, config/queue.yml, and config/database.yml,
# so the pool always follows the thread counts.
#
# - RAILS_MAX_THREADS: Puma threads in each Puma process (default 3). WEB_CONCURRENCY (Puma processes) is read by
#   Puma itself.
# - JOB_THREADS: threads of each Solid Queue worker process for the default queue and every other (default 3).
# - JOB_CONCURRENCY: how many of those worker processes (default 1).
# - JOB_REALTIME_THREADS: threads of the one worker process that serves only the realtime queue (default 1).
# - EVALUATION_THREADS: threads of the one worker process that serves only the evaluation queue, fleet-wide CIS
#   evaluation and advisory re-matching in batches (default 2, #197).
#
# Each must be a whole number from 1 to MAX; anything else (an empty value too) stops the boot, naming the setting.
#
# Plain Ruby, loaded before the application by config/puma.rb and config/application.rb.
module ProcessSizing
  MAX = 64
  # Solid Queue needs a worker's threads plus 2 connections to the queue database: one for polling and one for
  # its heartbeat (its own estimate, SolidQueue::Configuration#estimated_database_pool_size_for_worker). Other
  # processes can use the whole pool on a database: Puma's request threads share the primary with Action Cable's
  # worker pool and event loop, and the scheduler runs the every-minute tasks at once. The connection budget in
  # docs/operations/scaling.md counts that.
  POOL_EXTRA = 2

  module_function

  def web_threads(env = ENV) = whole("RAILS_MAX_THREADS", 3, env)
  def job_threads(env = ENV) = whole("JOB_THREADS", 3, env)
  def job_processes(env = ENV) = whole("JOB_CONCURRENCY", 1, env)
  def realtime_threads(env = ENV) = whole("JOB_REALTIME_THREADS", 1, env)
  def evaluation_threads(env = ENV) = whole("EVALUATION_THREADS", 2, env)

  # The most connections one process may hold to each database (max_connections in config/database.yml). Every
  # process reads the same file, so the pool fits the largest of them; a pool is a ceiling, and connections are
  # opened only when a thread needs one. With the defaults: 3 + 2 = 5.
  def database_pool(env = ENV)
    [ web_threads(env), job_threads(env), realtime_threads(env), evaluation_threads(env) ].max + POOL_EXTRA
  end

  def whole(name, default, env)
    value = env.fetch(name, default.to_s)
    number = value.to_s.match?(/\A\d+\z/) ? value.to_i : 0
    return number if number.between?(1, MAX)

    raise ArgumentError, "#{name} must be a whole number from 1 to #{MAX}, not #{value.inspect}"
  end
  private_class_method :whole
end
