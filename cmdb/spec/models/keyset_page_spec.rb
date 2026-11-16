require "rails_helper"

# Keyset pages of the fleet list and the compliance page (#193): every sort, in both directions, walked a page at a
# time forward and back, lists the same hosts in the same order as one unpaged read, through NULLs and tied names; each
# sort reads an index of host_compliance_summaries in order; and the edges of a cursor.
RSpec.describe KeysetPage do
  let!(:hosts) do
    now = Time.current
    rules = compliance_rules(1).values.flatten
    list = [ [ "Twin", %w[lab web], "1.2.0", :online ], [ "twin", [], "1.10.0", :stale ], [ "Alpha", %w[lab], "0.9.0", :offline ], [ "Beta", %w[web], nil, :never ],
             [ "Gamma", %w[lab], "1.2.0-rc.1", :online ], [ "Delta", [], "1.2.0", :online ] ].map do |name, tags, version, seen|
      host = enrolled_host(name:, tags:).first
      travel_to(now - { online: 0, stale: 10.minutes, offline: 2.hours }.fetch(seen, 0)) { record_heartbeat(host, agent_version: version) } unless seen == :never
      host
    end
    Liveness.evaluate!(now:)
    record_inventory(list[0])
    record_inventory(list[2], os: { "id" => "alpine", "version_id" => "3.20", "pretty_name" => "Alpine Linux v3.20" })
    cis_results!(list[0], rules.to_h { |r| [ r, "pass" ] })
    cis_results!(list[1], rules.to_h { |r| [ r, r.current_version.severity == "low" ? "pass" : "fail" ] })
    cis_results!(list[4], rules.to_h { |r| [ r, "fail" ] })
    vulns_evaluated!(list[0])
    findings!(list[1], "high", "low")
    findings!(list[3], "critical")
    vulns_evaluated!(list[5])
    list + [ create(:host, name: "Pending one", tags: %w[lab]), create(:host, :revoked, name: "Revoked one"), create(:host, :retired, name: "Retired one") ]
  end

  def walk(klass, params)
    first = klass.new(params)
    forward = first.public_send(klass == FleetList ? :hosts : :rows).map { |row| klass == FleetList ? row.id : row.host.id }
    pages = [ first ]
    pages << klass.new(params.merge(after: pages.last.page.next[:after].to_s)) while pages.last.page.next
    forward = pages.flat_map { |list| list.page.rows.map(&:id) }
    backward = pages.last.page.rows.map(&:id)
    list = pages.last
    while list.page.previous
      list = klass.new(params.merge(before: list.page.previous[:before].to_s))
      backward = list.page.rows.map(&:id) + backward
    end
    [ forward, backward ]
  end

  it "walks every fleet list sort a page at a time, forward and back, in the order of one unpaged read" do
    FleetList::SORTS.each_key do |sort|
      %w[asc desc].each do |dir|
        everything = FleetList.new(sort:, dir:).hosts.map(&:id)
        expect(everything.size).to eq(8)
        stub_const("FleetList::PER_PAGE", 3)
        expect(walk(FleetList, { sort:, dir: })).to eq([ everything, everything ]), "#{sort} #{dir}"
        stub_const("FleetList::PER_PAGE", 100)
      end
    end
  end

  it "walks every compliance sort a page at a time, forward and back, in the order of one unpaged read" do
    FleetCompliance::SORTS.each_key do |sort|
      everything = FleetCompliance.new(sort:).rows.map { |row| row.host.id }
      expect(everything.size).to eq(6)
      stub_const("FleetCompliance::PER_PAGE", 2)
      expect(walk(FleetCompliance, { sort: })).to eq([ everything, everything ]), sort
      stub_const("FleetCompliance::PER_PAGE", 100)
    end
  end

  it "keeps a filter and its sort across pages" do
    params = { tag: "lab", sort: "tags", dir: "desc" }
    everything = FleetList.new(params).hosts.map(&:id)
    stub_const("FleetList::PER_PAGE", 2)
    expect(walk(FleetList, params)).to eq([ everything, everything ])
    expect([ everything.size, FleetList.new(tag: "lab").total ]).to eq([ 4, 4 ])
  end

  it "starts at the first page for a cursor naming no host, and goes on from a host that left the filters" do
    stub_const("FleetList::PER_PAGE", 2)
    first = FleetList.new.page
    expect(FleetList.new(after: "999999999").page.rows).to eq(first.rows)
    alpha = hosts[2]
    expect(FleetList.new(after: alpha.id.to_s, tag: "web").page.rows.map(&:name)).to eq([ "Beta", "Twin" ])
    expect(FleetList.new(after: hosts[8].id.to_s).page.rows.map(&:name)).to eq([ "Revoked one", "Twin" ]) # retired: still a position
  end

  it "ends a full last page without a Next link, and gives an empty list no links" do
    stub_const("FleetList::PER_PAGE", 4)
    second = FleetList.new(after: FleetList.new.page.next[:after].to_s).page
    expect([ second.rows.size, second.next, second.previous ]).to eq([ 4, nil, { before: second.rows.first.id } ])
    empty = FleetList.new(q: "nothing like this").page
    expect([ empty.rows, empty.previous, empty.next ]).to eq([ [], nil, nil ])
    past = FleetList.new(after: hosts.last(3).first(2).last.id.to_s, q: "Pending").page
    expect([ past.rows, past.previous, past.next ]).to eq([ [], nil, nil ])
  end

  it "fills the first page when Previous lands on it, even after hosts before the cursor went" do
    stub_const("FleetList::PER_PAGE", 3)
    second = FleetList.new(after: FleetList.new.page.next[:after].to_s).page
    hosts.find { |h| h.name == "Alpha" }.retire!(actor: Audit::SYSTEM)
    back = FleetList.new(before: second.previous[:before].to_s).page
    expect(back.rows.map(&:name)).to eq(%w[Beta Delta Gamma])
    expect([ back.previous, back.next ]).to eq([ nil, { after: back.rows.last.id } ])
  end

  it "reads only well-formed cursors, and before when both are given" do
    expect(described_class.cursor(after: "12", before: "")).to eq(after: 12)
    expect(described_class.cursor(after: "12", before: "7")).to eq(before: 7)
    expect(described_class.cursor(after: "012", before: "-1")).to eq({})
    expect(described_class.cursor(after: "1" * 19)).to eq({})
  end

  describe "index use" do
    # The statement a page sends for its rows, explained with sequential scans, bitmap scans, and sorts off: a sort
    # has an index if the planner then reads one of host_compliance_summaries' in order (the test tables are too
    # small for it to choose one otherwise).
    def plan(list)
      statements = []
      callback = lambda do |*, event|
        binds = event[:type_casted_binds].then { |b| b.respond_to?(:call) ? b.call : b }
        statements << event[:sql].gsub(/\$(\d+)/) { ActiveRecord::Base.connection.quote(binds[Regexp.last_match(1).to_i - 1]) } if event[:sql].include?("LIMIT")
      end
      ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { list.page }
      sql = statements.last
      ActiveRecord::Base.transaction do
        %w[enable_seqscan enable_bitmapscan enable_sort].each { |setting| ActiveRecord::Base.connection.execute("SET LOCAL #{setting} = off") }
        ActiveRecord::Base.connection.select_values("EXPLAIN #{sql}").join("\n")
      end
    end

    it "reads each fleet list sort but last seen from an index of the summaries, on the first page and after a cursor" do
      cursor = hosts[2].id.to_s
      FleetList::SORTS.each_key do |sort|
        %w[asc desc].each do |dir|
          index = sort
          [ {}, { after: cursor }, { before: cursor } ].each do |at|
            explained = plan(FleetList.new(sort:, dir:, **at))
            if sort == "last_seen" # no index: last_seen_at changes on every heartbeat, so the fleet is sorted (ADR 0029)
              expect(explained).to match(/Sort Key: [^\n]*liveness(_\d+)?\.last_seen_at/)
            else
              # Either direction's index of the key will do: the planner may read one backwards on these tiny tables.
              expect(explained).to match(/host_compliance_summaries_#{index.delete_suffix('_desc')}(_desc)? /), "#{sort} #{dir} #{at}:\n#{explained}"
            end
          end
        end
      end
    end

    it "reads each compliance sort from an index of the summaries" do
      cursor = hosts[2].id.to_s
      { "worst" => "worst", "pass_rate" => "cis", "vulns" => "vulns_desc", "name" => "name" }.each do |sort, index|
        [ {}, { after: cursor }, { before: cursor } ].each do |at|
          explained = plan(FleetCompliance.new(sort:, **at))
          expect(explained).to include("host_compliance_summaries_#{index} "), "#{sort} #{at}:\n#{explained}"
        end
      end
    end
  end
end
