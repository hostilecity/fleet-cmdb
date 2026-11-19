require "rails_helper"

# Content-addressed package sets (#196, ADR 0028 decisions 1, 2, 6, and 8).
RSpec.describe PackageStore do
  def package(*fields) = AgentApi::PackageReport::Package.new(*fields)

  let(:now) { Time.utc(2026, 11, 16, 12) }

  # A random list of count packages from sources: some with no source, some multi-arch.
  def random_list(random, count: 200)
    Array.new(count) do |i|
      source = random.rand < 0.2 ? nil : "src-#{random.rand(count / 3)}"
      package("pkg-#{i}", random.rand < 0.1 ? "i386" : "amd64", "#{random.rand(5)}.#{random.rand(20)}-#{random.rand(3)}", source)
    end.uniq(&:key)
  end

  def chunk_ids(set_id) = PackageSet.find(set_id).chunk_ids

  describe "properties, on random lists" do
    it "reads a stored list back as it was, gives the same set whatever the order, and shares chunks between sets" do
      random = Random.new(196)
      5.times do
        list = random_list(random)
        id = described_class.store!(list.shuffle(random:), now:)
        expect(described_class.packages(id)).to eq(list.sort_by(&:key))
        expect(described_class.store!(list.shuffle(random:), now:)).to eq(id)
        expect(PackageSet.find(id)).to have_attributes(package_count: list.size)
      end
    end

    it "changes only the chunks of the sources a change touches: one for a version, two for a package whose source changes" do
      random = Random.new(7)
      list = random_list(random)
      before = chunk_ids(described_class.store!(list, now:))
      sourced = list.find(&:source)
      upgraded = list.map { |p| p == sourced ? p.with(version: "#{p.version}+deb13u1") : p }
      after = chunk_ids(described_class.store!(upgraded, now:))
      expect((0...64).reject { |b| before[b] == after[b] }).to eq([ described_class.bucket(sourced.source) ])

      moved = list.map { |p| p == sourced ? p.with(source: "another-source") : p }
      buckets = [ sourced.source, "another-source" ].map { |name| described_class.bucket(name) }.uniq.sort
      after = chunk_ids(described_class.store!(moved, now:))
      expect((0...64).reject { |b| before[b] == after[b] }).to eq(buckets)
    end

    it "buckets a package with no source by its own name" do
      id = described_class.store!([ package("curl", "amd64", "8.14.1-1", nil) ], now:)
      expect(chunk_ids(id).each_index.select { |b| chunk_ids(id)[b] }).to eq([ described_class.bucket("curl") ])
    end

    it "stores an empty list as an empty set, distinct from any other" do
      empty = described_class.store!([], now:)
      expect(PackageSet.find(empty)).to have_attributes(package_count: 0, chunk_ids: Array.new(64))
      expect(described_class.packages(empty)).to eq([])
      expect(described_class.packages(nil)).to eq([])
      expect(described_class.store!([ package("a", "amd64", "1", nil) ], now:)).not_to eq(empty)
    end

    it "diffs two sets by the chunks that differ, and finds names in the whole set" do
      list = random_list(Random.new(3))
      a = described_class.store!(list, now:)
      changed = list.first(1).map { |p| p.with(version: "9:#{p.version}") }
      b = described_class.store!(changed + list.drop(1), now:)
      older, newer = described_class.differing_packages(a, b)
      expect(older).to include(list.first)
      expect(newer).to include(changed.first)
      expect(older.size).to be < list.size
      expect(described_class.listed_names(b, [ list.last.name, "not-there" ])).to eq(Set[list.last.name])
      expect(described_class.listed_names(b, [])).to eq(Set.new)
    end
  end

  describe "reuse and touching" do
    let(:list) { [ package("openssl", "amd64", "3.5.0-1", "openssl"), package("curl", "amd64", "8.14.1-1", "curl") ] }

    it "touches a reused set only once it is more than a day old" do
      id = described_class.store!(list, now:)
      described_class.store!(list, now: now + 12.hours)
      expect(PackageSet.find(id).last_used_at).to eq(now)
      described_class.store!(list, now: now + 25.hours)
      expect(PackageSet.find(id).last_used_at).to eq(now + 25.hours)
    end

    it "touches a reused chunk in a new set once it is more than a day old" do
      described_class.store!(list, now:)
      described_class.store!(list.first(1), now: now + 25.hours)
      openssl = PackageChunk.find_by!(bucket: described_class.bucket("openssl"), package_count: 1)
      expect(openssl.last_used_at).to eq(now + 25.hours)
    end

    it "stores a set again by its hash when it was collected after it was read (the delete won)" do
      id = described_class.store!(list, now:)
      allow(PackageSet).to receive(:where).and_wrap_original do |original, *args, **kwargs|
        original.call(*args, **kwargs).tap { PackageSet.where(id:).delete_all if kwargs.key?(:content_hash) && PackageSet.unscoped.exists?(id) }
      end
      again = described_class.store!(list, now: now + 3.days)
      expect(again).not_to eq(id)
      expect(described_class.packages(again)).to eq(list.sort_by(&:key))
    end

    it "stores a chunk again by its hash when it was collected after it was read" do
      described_class.store!(list, now:)
      PackageSet.delete_all
      allow(PackageChunk).to receive(:where).and_wrap_original do |original, *args, **kwargs|
        original.call(*args, **kwargs).tap { |scope| PackageChunk.unscoped.delete_all if kwargs.key?(:content_hash) && scope.exists? && caller.none?(/insert_chunks/) }
      end
      id = described_class.store!(list, now: now + 3.days)
      expect(described_class.packages(id)).to eq(list.sort_by(&:key))
    end

    it "reads a chunk another report stored meanwhile instead of storing it twice" do
      other = true
      allow(PackageChunk).to receive(:insert_all).and_wrap_original do |original, rows, **options|
        if other # the other report stores the same chunks, with their entries, just before this one
          other = false
          described_class.send(:insert_chunks, described_class.chunks(list), now)
        end
        original.call(rows, **options)
      end
      id = described_class.store!(list, now:)
      expect(described_class.packages(id)).to eq(list.sort_by(&:key))
    end
  end

  describe ".collect!" do
    let(:list) { [ package("openssl", "amd64", "3.5.0-1", "openssl") ] }

    it "keeps the set a host's findings were last moved from while a resolution may read it, then lets it go (review of #240)" do
      allow(VulnerabilityMatchJob).to receive(:perform_later)
      host = debian_host
      import_advisories(osv_record(id: "DSA-1-1", fixed: "3.5.1-1"))
      VulnerabilityMatcher.match!([ host.id ])
      previous = HostVulnerabilityEvaluation.find_by!(host:).package_set_id
      report_packages(host, [ [ "openssl", "3.5.1-1", "openssl" ] ]) # fixed, not matched yet
      PackageSet.update_all(last_used_at: now - 10.days)
      PackageChunk.update_all(last_used_at: now - 10.days)
      PackageSnapshot.where(host_id: host.id).delete_all # as dropped partitions would
      described_class.collect!(now:)
      expect(PackageSet.exists?(previous)).to be(true) # the evaluation still names it
      VulnerabilityMatcher.match!([ host.id ])
      expect(VulnerabilityFinding.with_details.sole).to have_attributes(state: "resolved", resolution: "fixed", source: "openssl", fixed_version: "3.5.1-1")
      described_class.collect!(now:)
      expect(PackageSet.exists?(previous)).to be(false)
      expect(described_class.check).to eq([])
    end

    it "keeps sets a host or snapshot references and chunks a kept set holds; deletes the rest once untouched for two days" do
      host = enrolled_host.first
      report_packages(host, [ [ "bash", "5.2.37-1", "bash" ] ])
      referenced = HostPackageSet.find_by!(host:).package_set_id
      PackageSet.where(id: referenced).update_all(last_used_at: now - 10.days)
      orphan = described_class.store!(list, now: now - 3.days)
      fresh = described_class.store!(list + [ package("vim", "amd64", "9.1", "vim") ], now: now - 1.day)

      expect(described_class.collect!(now:, dry_run: true)).to eq("package_sets" => 1, "package_chunks" => 0)
      expect(PackageSet.exists?(orphan)).to be(true)
      counts = described_class.collect!(now:, batch_size: 1)
      expect(counts).to eq("package_sets" => 1, "package_chunks" => 0) # the openssl chunk is still held by the fresh set
      expect(PackageSet.where(id: [ referenced, orphan, fresh ]).pluck(:id)).to contain_exactly(referenced, fresh)

      PackageSet.where(id: fresh).delete_all
      PackageChunk.update_all(last_used_at: now - 3.days)
      expect(described_class.collect!(now:)).to eq("package_sets" => 0, "package_chunks" => 2) # openssl and vim; bash's is held
      expect(described_class.packages(referenced).map(&:name)).to eq(%w[bash])
    end

    it "keeps a set only a snapshot set aside by the default repair references, until it is moved back (ADR 0027, #239)" do
      host = enrolled_host.first
      report_packages(host, [ [ "bash", "5.2.37-1", "bash" ] ])
      id = PackageSnapshot.find_by!(host_id: host.id).package_set_id
      c = ActiveRecord::Base.connection
      c.execute("CREATE TABLE package_snapshots_default_moving (LIKE package_snapshots)")
      c.execute("WITH moved AS (DELETE FROM package_snapshots WHERE host_id = #{host.id} RETURNING *) INSERT INTO package_snapshots_default_moving SELECT * FROM moved")
      HostPackageSet.where(host_id: host.id).delete_all
      PackageSet.where(id:).update_all(last_used_at: now - 10.days)

      expect(described_class.collect!(now:)["package_sets"]).to eq(0)
      expect(PackageSet.exists?(id)).to be(true)
      c.execute("DROP TABLE package_snapshots_default_moving")
      expect(described_class.collect!(now:)["package_sets"]).to eq(1)
    end

    it "sweeps sets under partition maintenance's lock, checked each batch, and leaves them while maintenance holds it (review of #249)" do
      orphan = described_class.store!(list, now: now - 3.days)
      checks = 0
      allow(SessionLock).to receive(:hold).and_wrap_original do |original, key, &block|
        expect(key).to eq(Partitions::LOCK_KEY.to_s)
        original.call(key) { |still_held| block.call(-> { checks += 1; still_held.call }) }
      end
      session = separate_session
      session.execute("SELECT pg_advisory_lock(#{Partitions::LOCK_KEY})")
      expect(described_class.collect!(now:)).to eq("package_sets" => 0, "package_chunks" => 0)
      expect(PackageSet.exists?(orphan)).to be(true)
      session.execute("SELECT pg_advisory_unlock(#{Partitions::LOCK_KEY})")
      expect(described_class.collect!(now:)["package_sets"]).to eq(1)
      expect(checks).to eq(1)
    ensure
      session&.disconnect!
    end

    it "skips a set touched after it was found, and the touch finds nothing after a delete: both orders (decision 8)" do
      id = described_class.store!(list, now: now - 3.days)
      allow(PackageSet).to receive(:where).and_wrap_original do |original, *args, **kwargs|
        scope = original.call(*args, **kwargs)
        PackageSet.unscoped.where(id:).update_all(last_used_at: now) if kwargs[:id].is_a?(Array) # the report touches it between the scan and the delete
        scope
      end
      expect(described_class.collect!(now:)["package_sets"]).to eq(0)
      expect(PackageSet.exists?(id)).to be(true)
    end
  end

  describe ".check" do
    it "reports snapshots and hosts with no set, and ids that name nothing" do
      host = enrolled_host.first
      report_packages(host, [ [ "bash", "5.2.37-1", "bash" ] ])
      expect(described_class.check).to eq([])
      PackageSnapshot.where(host_id: host.id).update_all(package_set_id: nil)
      HostPackageSet.where(host_id: host.id).update_all(package_set_id: 0)
      PackageSet.update_all("chunk_ids[1] = -1")
      expect(described_class.check).to contain_exactly("1 dpkg package snapshots with no package set", "1 hosts naming a package set that is not stored",
                                                       "1 package sets naming a chunk that is not stored")
    end
  end
end
