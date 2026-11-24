require "rails_helper"

# The fleet list query (FR-1.5, P1-D02).
RSpec.describe FleetList do
  def names(params = {}) = described_class.new(params).hosts.map(&:name)

  let!(:media) { enrolled_host(name: "Media server", hostname: "vm-01.example.lan", tags: %w[media lab]).first }
  let!(:web) { enrolled_host(name: "web A", hostname: "vm-02.example.lan", tags: %w[web]).first }
  let!(:build) { enrolled_host(name: "Build runner", hostname: "ci-01.example.lan", tags: %w[ci lab]).first }
  let!(:waiting) { enrolled_host(name: "DNS resolver", hostname: "vm-05.example.lan", tags: %w[infra]).first }
  let!(:pending) { create(:host, name: "Lab sandbox", hostname: "vm-06.example.lan", tags: %w[lab]) }
  let!(:revoked) { create(:host, :revoked, name: "Old proxy", hostname: "vm-07.example.lan", tags: %w[web]) }
  let!(:retired) { create(:host, :retired, name: "Gone", hostname: "vm-08.example.lan", tags: %w[lab]) }

  before do
    now = Time.current
    record_heartbeat(media)
    travel_to(now - 10.minutes) { record_heartbeat(build) }
    travel_to(now - 2.hours) { record_heartbeat(web) }
    Liveness.evaluate!(now:)
    record_inventory(media)
    record_inventory(web, os: { "id" => "alpine", "version_id" => "3.20", "pretty_name" => "Alpine Linux v3.20" })
  end

  it "lists the fleet without retired hosts, by name" do
    expect(names).to eq([ "Build runner", "DNS resolver", "Lab sandbox", "Media server", "Old proxy", "web A" ])
  end

  it "counts active hosts by liveness with pending and revoked apart, ignoring retired hosts" do
    expect(described_class.counts).to eq("online" => 1, "stale" => 1, "offline" => 1, "awaiting" => 1, "pending" => 1, "revoked" => 1)
  end

  it "counts in one query" do
    expect(count_queries { described_class.counts }).to eq(1)
  end

  it "lists tags in use in the fleet only" do
    expect(described_class.tags).to eq(%w[ci infra lab media web])
  end

  describe "search" do
    it "matches name or hostname, case-insensitively" do
      expect(names(q: "MEDIA")).to eq([ "Media server" ])
      expect(names(q: "ci-01")).to eq([ "Build runner" ])
    end

    it "treats LIKE wildcards literally" do
      expect(names(q: "%")).to eq([])
      expect(names(q: "_")).to eq([])
    end
  end

  describe "filters" do
    it "filters by each status" do
      expect(names(status: "online")).to eq([ "Media server" ])
      expect(names(status: "stale")).to eq([ "Build runner" ])
      expect(names(status: "offline")).to eq([ "web A" ])
      expect(names(status: "awaiting")).to eq([ "DNS resolver" ])
      expect(names(status: "pending")).to eq([ "Lab sandbox" ])
      expect(names(status: "revoked")).to eq([ "Old proxy" ])
    end

    it "filters by tag, normalising it" do
      expect(names(tag: " LAB ")).to eq([ "Build runner", "Lab sandbox", "Media server" ])
    end

    it "filters to the hosts without recovery mode, with the other filters (#232)" do
      # Media server reports it set up, web A not set up, Build runner does not report it; DNS resolver has sent no
      # heartbeat, and pending and revoked hosts are not active, so the question does not arise for them.
      media.update_columns(agent_recovery_coverage: "set_up")
      web.update_columns(agent_recovery_coverage: "not_set_up")
      [ pending, revoked ].each { |h| h.update_columns(agent_recovery_coverage: "not_set_up", first_seen_at: 1.day.ago) }
      expect(names(recovery: "missing")).to eq([ "Build runner", "web A" ])
      # Not checked counts as not set up too: it is not known to be (re-review of #235).
      build.update_columns(agent_recovery_coverage: "unchecked")
      expect(names(recovery: "missing")).to eq([ "Build runner", "web A" ])
      build.update_columns(agent_recovery_coverage: nil)
      expect(names(recovery: "missing", tag: "lab")).to eq([ "Build runner" ])
      expect(names(recovery: "missing", status: "online")).to eq([])
      list = described_class.new(recovery: "missing", sort: "status")
      expect([ list.filtered?, list.total ]).to eq([ true, 2 ])
      expect(list.list_params).to eq(recovery: "missing", sort: "status")
      expect(list.sort_params("name")).to eq(recovery: "missing", sort: "name", dir: "asc")
      expect(described_class.new(recovery: "everything").recovery).to be_nil
    end

    # As the heartbeat stores them (Liveness.process_columns): the (limit + 1)th newest restart in the indexed column.
    def restarted(host, times) = host.update_columns(agent_restarted_at: times.first, agent_recent_restarts: times,
                                                     agent_restart_loop_at: times[Rollouts.restart_loop.limit])

    it "filters to the hosts whose agent restarted more than the limit within the window, with the other filters (#251)" do
      now = Time.current
      restarted(media, [ now - 1.hour ] * 4)  # 4 in a day
      restarted(web, [ now - 1.hour ] * 3)    # exactly 3: no
      restarted(build, [ now - 2.hours ] * 3 + [ now - 25.hours ])
      restarted(revoked, [ now - 1.hour ] * 9) # not retired: listed
      restarted(retired, [ now - 1.hour ] * 9)
      expect(names(restarts: "loop")).to eq([ "Media server", "Old proxy" ])
      expect(names(restarts: "loop", tag: "lab")).to eq([ "Media server" ])
      expect(names(restarts: "loop", status: "online")).to eq([ "Media server" ])
      # The settings in force: more than 2 in 48 hours takes in Build runner's, and web A's.
      Rails.configuration.x.restart_loop.limit = 2
      Rails.configuration.x.restart_loop.window = 48.hours
      expect(Host.refresh_restart_loops!(batch: 2)).to eq(2) # a lower limit: web A's and Build runner's stored times move (S1)
      expect(Host.refresh_restart_loops!).to eq(0)
      expect(names(restarts: "loop")).to eq([ "Build runner", "Media server", "Old proxy", "web A" ])
      expect(described_class.restart_filter_label).to eq("More than 2 times in 48 hours")
      list = described_class.new(restarts: "loop", sort: "status")
      expect([ list.filtered?, list.only_restart_filter?, list.only_recovery_filter? ]).to eq([ true, true, false ])
      expect(list.list_params).to eq(restarts: "loop", sort: "status")
      expect(list.sort_params("name")).to eq(restarts: "loop", sort: "name", dir: "asc")
      expect(described_class.new(restarts: "lots").restarts).to be_nil
      expect(described_class.new(restarts: "loop", recovery: "missing").only_restart_filter?).to be(false)
    end

    it "reads the restart filter from a partial index of the hosts that loop (#251, review of #307, S1)" do
      # Structural, as for the recovery-mode index: the filter's first condition is a range on the indexed column,
      # which implies the index's predicate.
      predicate, columns = Host.connection.select_rows(<<~SQL).first
        SELECT pg_get_expr(i.indpred, i.indrelid), pg_get_indexdef(i.indexrelid) FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
         WHERE c.relname = 'index_hosts_restart_loops'
      SQL
      expect(predicate).to eq("(agent_restart_loop_at IS NOT NULL)")
      expect(columns).to include("(agent_restart_loop_at)")
      expect(FleetList::RESTART_LOOP).to start_with("hosts.agent_restart_loop_at >= :since AND ")
      plan = Host.connection.select_values("EXPLAIN #{described_class.new(restarts: 'loop').scope.to_sql}").join("\n")
      expect(plan).to include("agent_recent_restarts")
    end

    it "has a partial index whose predicate is exactly the recovery-mode filter (#232)" do
      # Structural rather than a plan: the planner's choice on a test database depends on its statistics (it
      # flaked on CI). PostgreSQL uses a partial index whenever the query's condition implies its predicate, which
      # an identical condition always does. The plans on 300k hosts were measured in the review of #235.
      predicate = Host.connection.select_value(<<~SQL)
        SELECT pg_get_expr(i.indpred, i.indrelid) FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
         WHERE c.relname = 'index_hosts_without_recovery_mode'
      SQL
      expect(predicate).to eq("(((enrollment_state)::text = 'active'::text) AND (first_seen_at IS NOT NULL) AND ((agent_recovery_coverage)::text IS DISTINCT FROM 'set_up'::text))")
      expect(FleetList::WITHOUT_RECOVERY_MODE.gsub("hosts.", "")).to eq(
        "enrollment_state = 'active' AND first_seen_at IS NOT NULL AND agent_recovery_coverage IS DISTINCT FROM 'set_up'"
      )
      migration = Rails.root.join("db/migrate/20261118232004_index_hosts_without_recovery_mode.rb").read
      expect(migration).to include(%(where: "#{FleetList::WITHOUT_RECOVERY_MODE.gsub('hosts.', '')}"))
    end


    it "ignores unknown statuses, sorts, and directions" do
      list = described_class.new(status: "retired", sort: "secret_digest", dir: "sideways")
      expect([ list.status, list.sort, list.direction ]).to eq([ nil, "name", "asc" ])
      expect(list.hosts.size).to eq(6)
    end

    it "composes search, tag, status, and sort" do
      expect(names(tag: "lab", status: "online")).to eq([ "Media server" ])
      expect(names(tag: "lab", q: "vm-0", sort: "name", dir: "desc")).to eq([ "Media server", "Lab sandbox" ])
      expect(names(tag: "web", q: "vm", status: "revoked")).to eq([ "Old proxy" ])
      expect(names(tag: "lab", status: "offline")).to eq([])
    end
  end

  describe "sorting" do
    it "sorts by status, most alive first, then name" do
      expect(names(sort: "status")).to eq([ "Media server", "Build runner", "web A", "DNS resolver", "Lab sandbox", "Old proxy" ])
    end

    it "sorts by last seen with never-seen hosts last in both directions" do
      expect(names(sort: "last_seen").first(3)).to eq([ "web A", "Build runner", "Media server" ])
      expect(names(sort: "last_seen", dir: "desc").first(3)).to eq([ "Media server", "Build runner", "web A" ])
      expect(names(sort: "last_seen").last).not_to be_in([ "web A", "Build runner", "Media server" ])
    end

    it "sorts by hostname, operating system, and agent version" do
      expect(names(sort: "hostname").first).to eq("Build runner")
      expect(names(sort: "os").first(2)).to eq([ "web A", "Media server" ])
      Host.where(id: build.id).update_all(agent_version: "0.10.0")
      Host.where(id: waiting.id).update_all(agent_version: "0.9.1-rc.1")
      expect(names(sort: "agent").first(4)).to eq([ "Media server", "web A", "DNS resolver", "Build runner" ]) # by release, not text
      expect(names(sort: "agent", dir: "desc").last(2)).to eq([ "Lab sandbox", "Old proxy" ]) # never reported: last
      Host.where(id: web.id).update_all(agent_version: "2147483648.0.0") # schema-valid, beyond a 32-bit int
      expect(names(sort: "agent", dir: "desc").first).to eq("web A")
    end
  end

  it "sorts by tags as displayed, untagged hosts last in both directions" do
    Host.where(id: waiting.id).update_all(tags: [])
    expect(names(sort: "tags").first(3)).to eq([ "Build runner", "Lab sandbox", "Media server" ]) # ci,lab / lab / media,lab
    expect(names(sort: "tags").last).to eq("DNS resolver")
    expect(names(sort: "tags", dir: "desc").first(2)).to eq([ "web A", "Old proxy" ].sort_by(&:downcase))
    expect(names(sort: "tags", dir: "desc").last).to eq("DNS resolver")
  end

  it "joins the operating system name onto each row" do
    rows = described_class.new.hosts.index_by(&:name)
    expect(rows["Media server"].os_name).to eq("Debian GNU/Linux 13 (trixie)")
    expect(rows["Lab sandbox"].os_name).to be_nil
  end

  it "builds sort links that keep the filters and toggle direction" do
    list = described_class.new(q: "vm", tag: "lab", sort: "name")
    expect(list.sort_params("name")).to eq(q: "vm", tag: "lab", sort: "name", dir: "desc")
    expect(list.sort_params("status")).to eq(q: "vm", tag: "lab", sort: "status", dir: "asc")
    expect([ list.aria_sort("name"), list.aria_sort("status") ]).to eq(%w[ascending none])
  end
end
