require "rails_helper"

# PackageSnapshotTimeline (P2-D03, review of #124): the snapshot list and the comparison pair, without a request.
RSpec.describe PackageSnapshotTimeline do
  let(:host) { enrolled_host.first }
  let(:start) { Time.utc(2026, 11, 6, 9, 0, 0) }
  let(:cache) { ActiveSupport::Cache::MemoryStore.new }

  def timeline = described_class.new(host.id, cache:)

  def report(packages, at:, **options) = travel_to(at) { report_packages(host, packages, **options) }

  def snapshots = PackageSnapshot.where(host_id: host.id).chronological.to_a

  def counts(entries) = entries.map { |entry| entry.summary&.counts }

  it "is empty for a host with no snapshot, and has no pair" do
    expect(timeline).to have_attributes(latest: nil, entries: [], more?: false, count: 0)
    expect(timeline.pair).to be_nil
  end

  it "lists the latest snapshots newest first, each with what changed since the readable one before it" do
    report([ [ "bash", "1.0", "bash" ] ], at: start)
    report([], at: start + 1.hour, manager: "unreadable", unsupported_reason: "dpkg-query failed")
    report([ [ "bash", "1.1", "bash" ] ], at: start + 2.hours)
    first, unreadable, latest = snapshots
    entries = timeline.entries
    expect(entries.map(&:snapshot)).to eq([ latest, unreadable, first ])
    expect(entries.map(&:previous)).to eq([ unreadable, first, nil ])
    expect(entries.map(&:first)).to eq([ false, false, true ])
    expect(counts(entries)).to eq([ { upgrade: 1 }, {}, nil ])
    expect(entries[1].summary).to have_attributes(available?: false, unavailable_reason: PackageDiff::UNREADABLE)
    expect(timeline.latest).to eq(latest)
    expect(timeline.last_readable).to eq(latest)
  end

  it "lists LIMIT snapshots, the last with no summary when the one before it is not listed" do
    (described_class::LIMIT + 1).times { |i| report([ [ "bash", "1.#{i}", "bash" ] ], at: start + i.hours) }
    entries = timeline.entries
    expect(entries.size).to eq(described_class::LIMIT)
    expect(timeline).to be_more
    expect(entries.last).to have_attributes(first: false, previous: snapshots.first)
    expect(entries.last.summary.counts).to eq(upgrade: 1)
  end

  it "loads rows without their package lists" do
    report([ [ "bash", "1.0", "bash" ] ], at: start)
    expect(timeline.latest.has_attribute?(:packages)).to be(false)
  end

  it "caches each pair's summary by the two ids, so a second timeline builds no diff" do
    report([ [ "bash", "1.0", "bash" ] ], at: start)
    report([ [ "bash", "1.1", "bash" ] ], at: start + 1.hour)
    timeline.entries
    expect(cache.read(described_class.cache_key(*snapshots.map(&:id)))).to eq("unavailable_reason" => nil, "counts" => { "upgrade" => 1 })
    expect(PackageDiff).not_to receive(:between)
    expect(counts(timeline.entries)).to eq([ { upgrade: 1 }, nil ])
  end

  it "computes a new pair after Retention prunes the snapshot between, never the pruned pair's summary" do
    report([ [ "bash", "1.0", "bash" ] ], at: start)
    report([ [ "bash", "1.1", "bash" ] ], at: start + 1.hour)
    report([ [ "bash", "1.1", "bash" ], [ "vim", "9.1", "vim" ] ], at: start + 2.hours)
    expect(counts(timeline.entries)).to eq([ { installed: 1 }, { upgrade: 1 }, nil ])
    PackageSnapshot.where(id: snapshots[1].id).delete_all
    expect(counts(timeline.entries)).to eq([ { installed: 1, upgrade: 1 }, nil ])
  end

  describe "#pair" do
    before do
      report([ [ "bash", "1.0", "bash" ] ], at: start)
      report([ [ "bash", "1.1", "bash" ] ], at: start + 1.hour)
      report([ [ "bash", "1.2", "bash" ] ], at: start + 2.hours)
    end

    it "is the latest against the one before it by default, with every snapshot pickable" do
      first, middle, latest = snapshots
      pair = timeline.pair
      expect(pair).to have_attributes(from: middle, to: latest, reversed: false)
      expect(pair.pickable).to eq([ [ latest, true, false ], [ middle, false, false ], [ first, false, true ] ])
      expect(pair.diff.upgraded.map(&:name)).to eq([ "bash" ])
    end

    it "compares a named to with the one before it, or the oldest with the one after it" do
      first, middle, = snapshots
      expect(timeline.pair(to: middle.id.to_s)).to have_attributes(from: first, to: middle)
      expect(timeline.pair(to: first.id.to_s)).to have_attributes(from: first, to: middle)
    end

    it "takes any two, and says when from is the later one" do
      first, _, latest = snapshots
      expect(timeline.pair(from: latest.id.to_s, to: first.id.to_s)).to have_attributes(from: latest, to: first, reversed: true)
    end

    it "refuses an id that is not this host's, even with nothing to compare" do
      other = enrolled_host.first
      travel_to(start) { report_packages(other, [ [ "bash", "1.0", "bash" ] ]) }
      foreign = PackageSnapshot.find_by!(host_id: other.id).id.to_s
      expect { timeline.pair(from: foreign) }.to raise_error(ActiveRecord::RecordNotFound)
      expect { described_class.new(other.id, cache:).pair(to: snapshots.first.id.to_s) }.to raise_error(ActiveRecord::RecordNotFound)
      expect(described_class.new(other.id, cache:).pair(to: foreign)).to be_nil
    end
  end
end
