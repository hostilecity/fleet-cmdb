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
    end
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
