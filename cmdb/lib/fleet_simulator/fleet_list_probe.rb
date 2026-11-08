module FleetSimulator
  # Times the dashboard every interval while the fleet reports, each page as a signed-in operator's browser would
  # load it (FR-1.5, NFR-3):
  #
  # - the fleet list, by default and sorted by status. Each sample notes how many of the simulated hosts the page
  #   listed, so a fast but incomplete page cannot pass for a fast one;
  # - with Phase 2 (P2-S12), the pages given as extra: the fleet compliance view, one host's vulnerabilities, and
  #   its package comparison. Each must answer 200 and contain the text expected of it.
  class FleetListProbe
    PATHS = [ "/", "/?sort=status" ].freeze

    # One extra page: the kind its samples are recorded as, the path, and text the page must contain.
    Page = Data.define(:kind, :path, :expect)

    def initialize(transport:, stats:, cookie:, host_names:, interval:, clock: Clock.new, pages: [])
      @transport = transport
      @stats = stats
      @cookie = cookie
      @host_names = host_names
      @interval = interval
      @clock = clock
      @pages = pages
      @next_at = nil
    end

    # Probes when one is due. Runs on the runner's loop thread, between scheduling rounds.
    def tick(now)
      return if @next_at && now < @next_at

      @next_at = now + @interval
      PATHS.each { |path| probe(path, now) }
      @pages.each { |page| probe_page(page, now) }
    end

    def probe(path, now)
      response = @transport.get_dashboard(path, cookie: @cookie)
      listed = response.success? ? @host_names.count { |name| response.body.include?(">#{name}<") } : 0
      note = "#{path} listed #{listed}/#{@host_names.size}"
      status = listed == @host_names.size ? response.status : "incomplete"
      @stats.record(kind: :fleet_list, host: nil, status:, ms: response.ms, at: now, note:)
    end

    def probe_page(page, now)
      response = @transport.get_dashboard(page.path, cookie: @cookie)
      complete = response.success? && response.body.include?(page.expect)
      @stats.record(kind: page.kind, host: nil, status: complete ? response.status : "incomplete", ms: response.ms, at: now,
                    note: complete ? page.path : "#{page.path} without #{page.expect.inspect}")
    end
  end
end
