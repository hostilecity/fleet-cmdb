require "rails_helper"
require Rails.root.join("db/migrate/20261116196003_backfill_package_sets")
require Rails.root.join("db/migrate/20261116196004_drop_host_packages")

# Moving an existing database's package lists into sets (#196, ADR 0028, "Migration from the current schema"). The
# old storage is put back for each example (inside its transaction), filled as the old code left it, and migrated.
RSpec.describe BackfillPackageSets do
  let(:connection) { ActiveRecord::Base.connection }

  def quiet(&) = ActiveRecord::Migration.suppress_messages(&)

  before do
    quiet do
      connection.create_table(:host_packages) do |t|
        t.bigint :host_id, null: false
        t.string :name, :architecture, :version, null: false
        t.string :source
      end
      connection.add_column :package_snapshots, :packages, :jsonb, null: false, default: []
      %i[source ecosystem installed_version fixed_version].each { |column| connection.add_column :vulnerability_findings, column, :string }
      connection.add_index :vulnerability_findings, %i[host_id source], name: "index_vulnerability_findings_on_host_id_and_source"
      connection.add_index :vulnerability_findings, %i[ecosystem source host_id], name: "index_vulnerability_findings_on_ecosystem_and_source"
    end
    HostPackageSet.reset_column_information
    PackageSnapshot.reset_column_information
  end

  after do
    PackageSnapshot.reset_column_information
    VulnerabilityFinding.reset_column_information
  end

  # A host as the old recorder left it: its set row, its package rows, and a snapshot with the JSON list.
  def old_host(rows, manager: "dpkg", reason: nil, hash: nil)
    host = enrolled_host.first
    hash ||= Digest::SHA256.hexdigest(rows.to_json)
    HostPackageSet.create!(host:, manager:, unsupported_reason: reason, package_count: rows.size, content_hash: hash, report_id: SecureRandom.uuid,
                           schema_version: 1, collected_at: Time.current, received_at: Time.current)
    rows.each { |name, version, source| connection.execute("INSERT INTO host_packages (host_id, name, architecture, version, source) VALUES (#{host.id}, '#{name}', 'amd64', '#{version}', #{source ? "'#{source}'" : 'NULL'})") }
    snapshot(host, manager == "dpkg" ? rows : [], manager:, reason:, hash:)
    host
  end

  def snapshot(host, rows, manager: "dpkg", reason: nil, hash: Digest::SHA256.hexdigest(rows.to_json))
    connection.execute(PackageSnapshot.sanitize_sql_array([ <<~SQL.squish, host.id, manager, reason, rows.size, hash, rows.map { |n, v, s| [ n, "amd64", v, s ] }.to_json ]))
      INSERT INTO package_snapshots (host_id, manager, unsupported_reason, package_count, content_hash, packages, report_id, collected_at, received_at)
      VALUES (?, ?, ?, ?, ?, ?::jsonb, gen_random_uuid(), now() - interval '200 days', now() - interval '200 days')
    SQL
  end

  def migrate = quiet { described_class.new.migrate(:up) }

  def set_of(host) = HostPackageSet.find_by!(host_id: host.id).package_set_id

  it "groups dpkg hosts by hash, builds unreadable hosts' sets from their own rows, and gives every dpkg snapshot its set" do
    list = [ [ "openssl", "3.5.0-1", "openssl" ], [ "curl", "8.14.1-1", nil ] ]
    a = old_host(list, hash: "same")
    b = old_host(list, hash: "same")
    # Two unreadable hosts with the same reason share a hash but not a list (the review's blocker).
    u1 = old_host([ [ "bash", "5.2-1", "bash" ] ], manager: "unreadable", reason: "dpkg broken", hash: "unreadable")
    u2 = old_host([ [ "zsh", "5.9-1", "zsh" ] ], manager: "unreadable", reason: "dpkg broken", hash: "unreadable")
    never = old_host([], manager: "unreadable", reason: "dpkg broken", hash: "unreadable")
    unsupported = old_host([], manager: "unsupported", reason: "no dpkg", hash: "unsupported")
    snapshot(a, [ [ "openssl", "3.4.0-1", "openssl" ] ]) # an older, JSON-only snapshot, kept as the host's newest one would be

    migrate

    expect(set_of(a)).to eq(set_of(b))
    expect(PackageStore.packages(set_of(a)).map(&:to_a)).to eq([ [ "curl", "amd64", "8.14.1-1", nil ], [ "openssl", "amd64", "3.5.0-1", "openssl" ] ])
    expect([ u1, u2 ].map { |host| PackageStore.packages(set_of(host)).map(&:name) }).to eq([ %w[bash], %w[zsh] ])
    expect([ set_of(never), set_of(unsupported) ]).to eq([ nil, nil ])
    old = PackageSnapshot.where(host_id: a.id).find_by(package_count: 1)
    expect(PackageStore.packages(old.package_set_id).map(&:version)).to eq([ "3.4.0-1" ])
    expect(PackageSnapshot.where(manager: "dpkg", package_set_id: nil)).to be_empty
    expect(PackageSnapshot.where.not(manager: "dpkg").pluck(:package_set_id).uniq).to eq([ nil ])

    quiet { DropHostPackages.new.migrate(:up) }
    expect(connection.table_exists?(:host_packages)).to be(false)
    expect(connection.column_exists?(:package_snapshots, :packages)).to be(false)
  end

  def old_finding(host, advisory, package)
    connection.execute(<<~SQL.squish)
      INSERT INTO vulnerability_findings (host_id, advisory_id, package, architecture, source, ecosystem, installed_version, fixed_version, state, first_seen_at, created_at, updated_at)
      VALUES (#{host.id}, #{advisory.id}, '#{package}', 'amd64', 'openssl', 'Debian:13', '3.5.0-1', '3.5.1-1', 'open', now(), now(), now())
    SQL
  end

  it "copies each finding's details to its last_ columns in batches, and names each host's set on its evaluation" do
    stub_const("PackageStoreBackfill::FINDINGS_BATCH", 1)
    host = old_host([ [ "openssl", "3.5.0-1", "openssl" ] ])
    advisory = Advisory.create!(advisory_id: "DSA-1-1", source: "test", severity: "high", modified_at: Time.current)
    %w[openssl libssl3].each { |package| old_finding(host, advisory, package) }
    HostVulnerabilityEvaluation.create!(host:, ecosystem: "Debian:13", state: "evaluated", evaluated_at: Time.current)
    statements = []
    ActiveSupport::Notifications.subscribed(->(*, payload) { statements << payload[:sql] if payload[:sql].match?(/\AUPDATE "?vulnerability_findings"?/) }, "sql.active_record") { migrate }
    expect(connection.select_rows("SELECT last_source, last_installed_version, last_fixed_version, last_ecosystem FROM vulnerability_findings").uniq)
      .to eq([ %w[openssl 3.5.0-1 3.5.1-1 Debian:13] ])
    expect(statements.size).to eq(2) # one batch of ids each
    expect(HostVulnerabilityEvaluation.find_by!(host:).package_set_id).to eq(set_of(host))
  end

  it "refuses at container start, changing nothing, when the work is too long, and the rake task does it, resumably" do
    stub_const("BackfillPackageSets::INLINE_SECONDS", 0.01)
    old_host([ [ "openssl", "3.5.0-1", "openssl" ] ])
    expect { migrate }.to raise_error(/fleet-cmdb upgrade step needed: moving the package lists .* more than 0.01 s \(it stopped counting there; bin\/rails packages:backfill prints what is left.* nothing was changed .*package-backfill.sh/m)
    expect(PackageSet.count).to eq(0)
    expect { quiet { DropHostPackages.new.migrate(:up) } }.to raise_error(/fleet-cmdb upgrade step needed: 2 dpkg package snapshots and hosts have no package set.*package-backfill.sh/m)

    log = []
    backfill = PackageStoreBackfill.new(log: ->(message) { log << message })
    # Two one-package lists on two rows, every package new.
    expect(backfill.estimate.counts).to eq("rows" => 2, "findings" => 0, "lists" => 2, "packages" => 2, "new_packages" => 2)
    holding_backfill_lock { expect { backfill.run! }.to raise_error(PackageStoreBackfill::Busy, /another package backfill is running/) }
    expect(PackageSet.count).to eq(0)
    expect(backfill.pending).to eq("hashes" => 2, "unreadable_hosts" => 0, "rows" => 2, "findings" => 0)
    backfill.run!
    expect(backfill.pending).to eq("hashes" => 0, "unreadable_hosts" => 0, "rows" => 0, "findings" => 0)
    expect(log).to include("hosts: 1 distinct package lists stored", "snapshots: 1 distinct package lists stored")
    expect(connection.select_value("SELECT count(*) FROM pg_class WHERE relname LIKE '%backfill_196'").to_i).to eq(0) # its indexes are gone
    migrate # nothing left: runs at once
    quiet { DropHostPackages.new.migrate(:up) }
    expect(backfill.pending).to eq("hashes" => 0, "unreadable_hosts" => 0, "rows" => 0, "findings" => 0)
    backfill.run!
    expect(log.last).to eq("nothing to move: host_packages is gone")
  end

  describe "the estimate (reviews of #240 and #250)" do
    let(:backfill) { PackageStoreBackfill.new }
    let(:rates) { PackageStoreBackfill }
    # 300 packages over many sources, so over most of the 64 buckets; the second list upgrades one of them.
    let(:list) { Array.new(300) { |i| [ "pkg-#{i}", "1.0-1", "src-#{i / 3}" ] } }
    let(:upgraded) { list.each_with_index.map { |(name, version, source), i| i == 7 ? [ name, "1.0-2", source ] : [ name, version, source ] } }

    def chunk_packages(*lists)
      lists.flat_map { |rows| PackageStore.chunks(rows.map { |n, v, s| PackageStore::Package.from_a([ n, "amd64", v, s ]) }) }
           .uniq(&:content_hash).sum { |chunk| chunk.packages.size }
    end

    it "charges every package of each distinct list, once per list however many rows carry it" do
      host = old_host(list) # its host row and one snapshot, both with the list's hash
      snapshot(host, list) # a second snapshot with that hash: one more row, not one more list
      counts = backfill.estimate.counts
      expect(counts).to eq("rows" => 3, "findings" => 0, "lists" => 2, "packages" => 600, "new_packages" => 600) # no limit: every package new
      expect(backfill.estimated_seconds).to be_within(1e-9).of((3 * rates::SECONDS_PER_ROW) + (2 * rates::SECONDS_PER_LIST) +
                                                              (600 * rates::SECONDS_PER_PACKAGE) + (600 * rates::SECONDS_PER_NEW_PACKAGE))
    end

    it "counts only the packages of the lists' distinct chunks when every package apart would not fit, as PackageStore chunks them" do
      host = old_host(list)
      snapshot(host, upgraded)
      # An unreadable host's own list (from its host_packages rows) is a list to move too.
      own = Array.new(40) { |i| [ "tool-#{i}", "0.#{i}-1", "toolsrc-#{i}" ] }
      old_host(own, manager: "unreadable", reason: "dpkg broken", hash: "unreadable")
      distinct = chunk_packages(list, upgraded, own)
      expect(distinct).to be < 400 + 40 # the two dpkg lists share all but one chunk
      base = (3 * rates::SECONDS_PER_ROW) + (4 * rates::SECONDS_PER_LIST) + (940 * rates::SECONDS_PER_PACKAGE)
      within = base + (((distinct + 940) / 2) * rates::SECONDS_PER_NEW_PACKAGE) # between the distinct chunks and the bound
      estimate = backfill.estimate(within:)
      expect(estimate.counts).to eq("rows" => 3, "findings" => 0, "lists" => 4, "packages" => 940, "new_packages" => distinct)
      expect(estimate).to be_complete
      expect(estimate.seconds).to be <= within
    end

    it "counts every package as new when counting the new chunks takes too long" do
      old_host(list)
      stub_const("PackageStoreBackfill::NEW_PACKAGES_TIMEOUT", "10ms")
      stub_const("PackageStoreBackfill::NEW_CHUNK_PACKAGES", "SELECT pg_sleep(1)")
      within = (2 * rates::SECONDS_PER_ROW) + (2 * rates::SECONDS_PER_LIST) + (600 * rates::SECONDS_PER_PACKAGE) + (300 * rates::SECONDS_PER_NEW_PACKAGE)
      expect(backfill).to receive(:new_chunk_packages).and_call_original # the bound does not fit, so it counts, and times out
      expect(backfill.estimate(within:).counts["new_packages"]).to eq(600)
      expect(connection.select_value("SHOW statement_timeout")).not_to eq("10ms")
    end

    it "stops counting once it is past the limit, reading no more rows than could fit" do
      4.times { old_host([ [ "openssl", "3.5.0-1", "openssl" ] ]) } # four rows in each table
      estimate = backfill.estimate(within: 1.5 * rates::SECONDS_PER_ROW)
      expect(estimate.counts).to eq("rows" => 2 + 2) # each table counted up to two rows, not four: past the limit, so it stops
      expect(estimate).not_to be_complete
      expect(estimate.seconds).to be > 1.5 * rates::SECONDS_PER_ROW
    end

    it "walks the findings by their ids, so sparse ids cost no more batches than rows" do
      stub_const("PackageStoreBackfill::FINDINGS_BATCH", 1)
      host = old_host([ [ "openssl", "3.5.0-1", "openssl" ] ])
      advisory = Advisory.create!(advisory_id: "DSA-1-1", source: "test", severity: "high", modified_at: Time.current)
      %w[openssl libssl3].each { |package| old_finding(host, advisory, package) }
      connection.execute("UPDATE vulnerability_findings SET id = 2000000000 WHERE package = 'libssl3'") # retention left a gap
      statements = []
      ActiveSupport::Notifications.subscribed(->(*, payload) { statements << payload[:sql] if payload[:sql].match?(/\AUPDATE "?vulnerability_findings"?/) }, "sql.active_record") { migrate }
      expect(statements.size).to eq(2)
      expect(VulnerabilityFinding.where(last_ecosystem: nil)).to be_empty
    end
  end

  it "says how long when the estimate counted everything and it is still too long" do
    old_host([ [ "openssl", "3.5.0-1", "openssl" ] ]) # one list on a host row and a snapshot: one chunk of one package
    rates = PackageStoreBackfill
    counted = (2 * rates::SECONDS_PER_ROW) + (2 * rates::SECONDS_PER_LIST) + (2 * rates::SECONDS_PER_PACKAGE)
    stub_const("BackfillPackageSets::INLINE_SECONDS", counted + (0.5 * rates::SECONDS_PER_NEW_PACKAGE)) # its one chunk does not fit
    expect { migrate }.to raise_error(/would take about 1 min, too long for container start/)
  end

  # Its session lock goes through SessionLock (#198): behind a transaction-mode pooler it is on the direct connection, and
  # a run whose lock was lost stops before its next batch, so two runs never work side by side; running it again
  # carries on.
  it "checks its lock before each batch, stops once it is lost, and carries on when run again" do
    stub_const("PackageStoreBackfill::BATCH", 1)
    old_host([ [ "openssl", "3.5.0-1", "openssl" ] ])
    old_host([ [ "curl", "8.14.1-1", nil ] ])
    checks = 0
    allow(SessionLock).to receive(:hold).and_wrap_original do |original, key, &block|
      original.call(key) { block.call(-> { raise SessionLock::Lost, "gone" if (checks += 1) == 2 }) }
    end
    backfill = PackageStoreBackfill.new

    expect { backfill.run! }.to raise_error(SessionLock::Lost)
    expect(backfill.pending["hashes"]).to eq(3) # one host list stored before the lock was lost, of four lists
    allow(SessionLock).to receive(:hold).and_call_original
    backfill.run!
    expect(backfill.pending).to eq("hashes" => 0, "unreadable_hosts" => 0, "rows" => 0, "findings" => 0)
  end

  it "rolls back to no sets" do
    old_host([ [ "openssl", "3.5.0-1", "openssl" ] ])
    migrate
    quiet { described_class.new.migrate(:down) }
    expect([ PackageSet.count, PackageChunk.count, HostPackageSet.where.not(package_set_id: nil).count ]).to eq([ 0, 0, 0 ])
  end

  describe DropHostPackages do
    it "refuses while a dpkg snapshot or host has no set, and is not reversible" do
      old_host([ [ "openssl", "3.5.0-1", "openssl" ] ])
      expect { quiet { described_class.new.migrate(:up) } }.to raise_error(/2 dpkg package snapshots and hosts have no package set/)
      expect(connection.table_exists?(:host_packages)).to be(true)
      expect { quiet { described_class.new.migrate(:down) } }.to raise_error(ActiveRecord::IrreversibleMigration)
    end
  end
end
