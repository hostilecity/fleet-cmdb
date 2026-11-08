module FleetSimulator
  # Drives the simulated hosts: each sends a heartbeat at once and then every heartbeat interval, and a full
  # inventory report at once and then every inventory interval (FR-1.2, FR-1.3), each spread by jitter so the
  # fleet does not report in lockstep. Due requests go to a pool of worker threads (concurrency 1 runs them
  # inline, which the specs use). A host never has two requests in flight at once, as an agent does not.
  class Runner
    # Spread of each interval, as a fraction of it, so hosts drift apart as agents do.
    JITTER = 0.1
    TICK = 0.05

    attr_reader :hosts, :stats

    def initialize(hosts:, transport:, payloads:, stats:, options:, clock: Clock.new, probe: nil)
      @hosts = hosts
      @transport = transport
      @payloads = payloads
      @stats = stats
      @options = options
      @clock = clock
      @probe = probe
      @lock = Mutex.new
    end

    # Spreads the first heartbeats over one interval, as agents started at different times would be. Hosts with
    # the stop behaviour go silent halfway through the run.
    def start(now)
      @hosts.each do |host|
        host.heartbeat_interval = @options.heartbeat_interval
        host.inventory_interval = @options.inventory_interval
        host.next_heartbeat_at = now + rand * host.heartbeat_interval
        host.next_inventory_at = host.next_heartbeat_at
        if @options.phase2 # configuration and package reports at startup, then every report interval (P2-S12)
          host.report_interval = @options.report_interval
          host.next_report_at = host.next_heartbeat_at
        end
        host.silent_at = now + @options.duration / 2 if host.stop?
      end
    end

    # Sends seed_snapshots inventory reports per host, each with a new kernel version, before the measured run,
    # so the run starts with accumulated history (NFR-3). Recorded as "seed", not as inventory.
    def seed_snapshots(count)
      # One job per host, its reports and any rate-limit waits in order on one worker, so a host never has two
      # requests in flight and its reports cannot overtake each other.
      dispatch(@hosts.map { |host| -> { count.times { seed(host) } } })
    end

    # Sends count configuration and package reports per host before the measured run, each a change: the SSH setting
    # flips and the next few vulnerable sources are upgraded (P2-S12). Recorded as "seed_reports".
    def seed_reports(count)
      dispatch(@hosts.map { |host| -> { count.times { seed_report(host) } } })
    end

    # Runs until deadline, then waits for requests in flight. Yields the time on every round, on this thread, for
    # whatever the caller checks as the run goes (the liveness check, progress lines).
    def run(deadline)
      @workers = start_workers
      loop do
        now = @clock.now
        break if now >= deadline

        due(now).each { |job| enqueue(job) }
        @probe&.tick(now)
        yield now if block_given?
        @clock.sleep(TICK)
      end
    ensure
      stop_workers
    end

    # Runs everything due at now, inline. Returns how many requests it sent.
    def step(now)
      jobs = due(now)
      jobs.each(&:call)
      jobs.size
    end

    # Requests due at now, as callables; claims the host so it is not picked again while in flight.
    def due(now)
      @lock.synchronize do
        @hosts.filter_map do |host|
          next if host.busy || host.credential.nil? || host.silent?(now)

          action = if now >= host.next_inventory_at then :inventory
          elsif host.next_report_at && now >= host.next_report_at then :reports
          elsif now >= host.next_heartbeat_at then :heartbeat
          end
          next unless action

          host.busy = true
          -> { perform(host, action) }
        end
      end
    end

    private

    def perform(host, action)
      case action
      when :inventory then inventory(host)
      when :reports then reports(host)
      else heartbeat(host)
      end
    ensure
      @lock.synchronize { host.busy = false }
    end

    def heartbeat(host)
      now = @clock.now
      response = @transport.post_api("/api/v1/heartbeat", @payloads.heartbeat(host, now:), credential: host.credential)
      record(:heartbeat, host, response, now)
      host.last_heartbeat_at = now if response.success?
      adopt_intervals(host, response)
      host.next_heartbeat_at = now + next_delay(host.heartbeat_interval, response)
    end

    def inventory(host)
      now = @clock.now
      report = @payloads.inventory(host, now:)
      response = @transport.post_api("/api/v1/reports/inventory", report, credential: host.credential)
      record(:inventory, host, response, now, note: host.behaviour)
      duplicate(host, report) if host.duplicates? && response.success?
      host.next_inventory_at = now + next_delay(host.inventory_interval, response)
      # The startup heartbeat goes out straight after the startup report, as the agent sends both at once.
      host.next_heartbeat_at = [ host.next_heartbeat_at, now ].min
    end

    # The configuration report, then the package report, as the agent sends them together (P2-A01). A churning host
    # changes both every time.
    def reports(host)
      now = @clock.now
      if host.churn?
        host.config_generation += 1
        host.package_generation += 1
      end
      config = @transport.post_api("/api/v1/reports/config", @payloads.config(host, now:), credential: host.credential)
      record(:config, host, config, now, note: host.behaviour)
      packages = @transport.post_api("/api/v1/reports/packages", @payloads.packages(host, now:), credential: host.credential)
      record(:packages, host, packages, now, note: host.behaviour)
      host.next_report_at = now + next_delay(host.report_interval, packages.retry_after ? packages : config)
    end

    def seed_report(host)
      host.config_generation += 1
      host.package_generation += 1
      { "/api/v1/reports/config" => :config, "/api/v1/reports/packages" => :packages }.each do |path, kind|
        now = @clock.now
        report = @payloads.public_send(kind, host, now:)
        loop do
          response = @transport.post_api(path, report, credential: host.credential)
          next @clock.sleep(response.retry_after) if response.retry_after

          break record(:seed_reports, host, response, now, note: kind.to_s)
        end
      end
    end

    # The same report again: the server must say it is a duplicate and store nothing new (AC-1.4).
    def duplicate(host, report)
      now = @clock.now
      response = @transport.post_api("/api/v1/reports/inventory", report, credential: host.credential)
      confirmed = response.success? && response.json["duplicate"] == true
      record(:duplicate, host, response, now, note: confirmed ? "duplicate" : "not recognised as a duplicate")
    end

    def seed(host)
      now = @clock.now
      report = @payloads.inventory(host, now:, change_stable: true)
      loop do
        response = @transport.post_api("/api/v1/reports/inventory", report, credential: host.credential)
        next @clock.sleep(response.retry_after) if response.retry_after

        break record(:seed, host, response, now)
      end
    end

    # The server may ask for other intervals (directives.intervals, ADR 0019); the simulator scales them too.
    def adopt_intervals(host, response)
      intervals = response.success? ? response.json.dig("directives", "intervals") : nil
      return unless intervals

      host.heartbeat_interval = intervals["heartbeat_seconds"] / @options.time_scale if intervals["heartbeat_seconds"]
      host.inventory_interval = intervals["inventory_seconds"] / @options.time_scale if intervals["inventory_seconds"]
    end

    def next_delay(interval, response)
      return response.retry_after if response.retry_after

      interval * (1 + JITTER * (2 * rand - 1))
    end

    def record(kind, host, response, at, note: nil)
      note = [ note, response.success? ? nil : response.body.to_s.first(200) ].compact.join(" ").presence
      @stats.record(kind:, host: host.name, status: response.status, ms: response.ms, at:, note:)
    end

    def dispatch(jobs)
      return jobs.each(&:call) if @options.concurrency == 1

      queue = Queue.new
      jobs.each { |job| queue << job }
      queue.close
      Array.new(@options.concurrency) { Thread.new { while (job = queue.pop) do job.call end } }.each(&:join)
    end

    def start_workers
      @queue = Queue.new
      return [] if @options.concurrency == 1

      Array.new(@options.concurrency) { Thread.new { while (job = @queue.pop) do job.call end } }
    end

    def enqueue(job) = @options.concurrency == 1 ? job.call : @queue << job

    def stop_workers
      @queue&.close
      @workers&.each(&:join)
    end
  end
end
