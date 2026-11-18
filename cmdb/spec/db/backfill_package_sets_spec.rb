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
    expect(statements.size).to be >= 2 # one batch of ids each
    expect(HostVulnerabilityEvaluation.find_by!(host:).package_set_id).to eq(set_of(host))
  end

  it "refuses at container start, changing nothing, when the work is too long, and the rake task does it, resumably" do
    stub_const("BackfillPackageSets::INLINE_SECONDS", 0.01)
    old_host([ [ "openssl", "3.5.0-1", "openssl" ] ])
    expect { migrate }.to raise_error(/fleet-cmdb upgrade step needed: moving 2 distinct package lists and 0 findings .* nothing was changed .*docker exec fleet-cmdb bin\/rails packages:backfill/m)
    expect(PackageSet.count).to eq(0)
    expect { quiet { DropHostPackages.new.migrate(:up) } }.to raise_error(/fleet-cmdb upgrade step needed: 2 dpkg package snapshots and hosts have no package set.*docker exec fleet-cmdb/m)

    log = []
    backfill = PackageStoreBackfill.new(log: ->(message) { log << message })
    expect(backfill.estimated_seconds).to eq(2 * PackageStoreBackfill::SECONDS_PER_LIST)
    holding_backfill_lock { expect { backfill.run! }.to raise_error(PackageStoreBackfill::Busy, /another package backfill is running/) }
    expect(PackageSet.count).to eq(0)
    expect(backfill.pending).to eq("hashes" => 2, "unreadable_hosts" => 0, "findings" => 0)
    backfill.run!
    expect(backfill.pending).to eq("hashes" => 0, "unreadable_hosts" => 0, "findings" => 0)
    expect(log).to include("hosts: 1 distinct package lists stored", "snapshots: 1 distinct package lists stored")
    expect(connection.select_value("SELECT count(*) FROM pg_class WHERE relname LIKE '%backfill_196'").to_i).to eq(0) # its indexes are gone
    migrate # nothing left: runs at once
    quiet { DropHostPackages.new.migrate(:up) }
    expect(backfill.pending).to eq("hashes" => 0, "unreadable_hosts" => 0, "findings" => 0)
    backfill.run!
    expect(log.last).to eq("nothing to move: host_packages is gone")
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
