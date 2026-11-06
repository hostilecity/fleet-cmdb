module FleetSimulator
  # Times the dashboard fleet list (FR-1.5, NFR-3) every interval while the fleet reports: the default list and the
  # list sorted by status, each as a signed-in operator's browser would load it. Each sample notes how many of the
  # simulated hosts the page listed, so a fast but incomplete page cannot pass for a fast one.
  class FleetListProbe
    PATHS = [ "/", "/?sort=status" ].freeze

    def initialize(transport:, stats:, cookie:, host_names:, interval:, clock: Clock.new)
      @transport = transport
      @stats = stats
      @cookie = cookie
      @host_names = host_names
      @interval = interval
      @clock = clock
      @next_at = nil
    end

    # Probes when one is due. Runs on the runner's loop thread, between scheduling rounds.
    def tick(now)
      return if @next_at && now < @next_at

      @next_at = now + @interval
      PATHS.each { |path| probe(path, now) }
    end

    def probe(path, now)
      response = @transport.get_dashboard(path, cookie: @cookie)
      listed = response.success? ? @host_names.count { |name| response.body.include?(">#{name}<") } : 0
      note = "#{path} listed #{listed}/#{@host_names.size}"
      status = listed == @host_names.size ? response.status : "incomplete"
      @stats.record(kind: :fleet_list, host: nil, status:, ms: response.ms, at: now, note:)
    end
  end
end
