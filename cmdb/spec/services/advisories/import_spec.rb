require "rails_helper"

# Importing OSV advisories from a file, a directory, or an archive (P2-S10, FR-2.4, DEC-11).
RSpec.describe Advisories::Import do
  let(:fixtures) { AdvisoryHelpers::OSV_FIXTURES }

  def import(path, full: false, **options)
    described_class.new(origin: "file", source: File.basename(path), full:, **options).call(Advisories::Reader.new(path))
  end

  def stored = Advisory.order(:advisory_id).pluck(:advisory_id, :modified_at, :updated_at, :withdrawn_reason)

  it "imports a directory of OSV records, keeping only the fleet's ecosystems, and reports the malformed one" do
    result = import(fixtures)
    expect(Advisory.pluck(:advisory_id)).to contain_exactly("DSA-9001-1", "DEBIAN-CVE-2026-90002")
    expect(AdvisoryPackage.pluck(:ecosystem, :package, :fixed_version))
      .to contain_exactly([ "Debian:13", "openssl", "3.5.1-1+deb13u1" ], [ "Debian:13", "curl", "8.14.1-2" ])
    expect(result.import).to have_attributes(state: "succeeded", origin: "file", source: "osv", full: false, ecosystems: [ "Debian:13" ],
                                             counts: include("records" => 4, "created" => 2, "skipped" => 1, "malformed" => 1, "rejected_urls" => 2),
                                             problems: [ { "location" => "malformed.json", "id" => nil, "problem" => "is not valid JSON" } ])
    expect(result.changed_packages).to eq("Debian:13" => %w[curl openssl])
  end

  it "audits each import with who, what source, and the counts" do
    operator = create(:operator)
    result = import(fixtures, operator:)
    entry = AuditEntry.where(action: Audit::Actions::ADVISORY_IMPORTED).sole
    expect(entry).to have_attributes(actor_type: "operator", actor_id: operator.id, target_type: "AdvisoryImport", target_id: result.import.id)
    expect(entry.changeset).to include("origin" => "file", "source" => "osv", "full" => false, "ecosystems" => "Debian:13",
                                       "counts" => include("created" => 2, "malformed" => 1))
    import(fixtures.join("DSA-9001-1.json"))
    expect(AuditEntry.where(action: Audit::Actions::ADVISORY_IMPORTED).last).to have_attributes(actor_type: "system", actor_id: nil)
  end

  it "re-importing the same data changes nothing" do
    import(fixtures)
    before = [ stored, AdvisoryPackage.order(:id).pluck(:id, :ranges) ]
    travel 1.hour do
      result = import(fixtures)
      expect(result.import.counts).to include("created" => 0, "updated" => 0, "unchanged" => 2, "withdrawn" => 0)
      expect(result.changed_packages).to eq({})
    end
    expect([ stored, AdvisoryPackage.order(:id).pluck(:id, :ranges) ]).to eq(before)
  end

  it "replaces an advisory with a newer version, and names the packages it affected before and after for re-matching" do
    import_advisories(osv_record(id: "DSA-1-1", package: "openssl", fixed: "3.5.1-1"))
    newer = osv_record(id: "DSA-1-1", package: "libssl3-source", fixed: "3.5.2-1", modified: "2026-10-21T00:00:00Z",
                       severity: [ { "type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } ])
    result = import_advisories(newer)
    expect(result.import.counts).to include("updated" => 1)
    expect(result.changed_packages).to eq("Debian:13" => %w[libssl3-source openssl])
    advisory = Advisory.sole
    expect(advisory).to have_attributes(modified_at: Time.utc(2026, 10, 21), severity: "critical")
    expect(advisory.packages.pluck(:package, :fixed_version)).to eq([ [ "libssl3-source", "3.5.2-1" ] ])
  end

  it "ignores an older version, so an old archive never moves data backwards" do
    import_advisories(osv_record(id: "DSA-1-1", fixed: "3.5.2-1", modified: "2026-10-21T00:00:00Z"))
    result = import_advisories(osv_record(id: "DSA-1-1", fixed: "3.5.1-1", modified: "2026-10-20T00:00:00Z"))
    expect(result.import.counts).to include("older" => 1, "updated" => 0)
    expect(result.changed_packages).to eq({})
    expect(AdvisoryPackage.sole.fixed_version).to eq("3.5.2-1")
  end

  it "keeps the newest of an id repeated in one import" do
    result = import(osv_zip("a.json" => osv_record(id: "DSA-1-1", fixed: "2", modified: "2026-10-21T00:00:00Z"),
                            "b.json" => osv_record(id: "DSA-1-1", fixed: "1", modified: "2026-10-20T00:00:00Z")))
    expect(Advisory.sole.modified_at).to eq(Time.utc(2026, 10, 21))
    expect(result.import.counts).to include("records" => 2, "created" => 1)
  end

  it "reports a malformed record with its location, id, and problem, and imports the valid ones" do
    bad = osv_record(id: "DSA-2-1", package: "Bad Name")
    result = import_advisories(osv_record(id: "DSA-1-1"), bad, "not json", osv_record(id: "DSA-3-1", modified: "soon"))
    expect(Advisory.pluck(:advisory_id)).to eq([ "DSA-1-1" ])
    expect(result.import.counts).to include("created" => 1, "malformed" => 3)
    expect(result.import.problems).to contain_exactly(
      { "location" => "DSA-2-1.json", "id" => "DSA-2-1", "problem" => "has affected[0] with an invalid package name" },
      { "location" => "record-2.json", "id" => nil, "problem" => "is not valid JSON" },
      { "location" => "DSA-3-1.json", "id" => "DSA-3-1", "problem" => "has a modified time that is not RFC 3339" }
    )
  end

  it "lists at most PROBLEM_LIMIT problems but counts them all" do
    stub_const("#{described_class}::PROBLEM_LIMIT", 2)
    result = import_advisories("x", "y", "z")
    expect(result.import.problems.size).to eq(2)
    expect(result.import.counts["malformed"]).to eq(3)
  end

  it "keeps and marks a withdrawn advisory, and names its packages so findings resolve" do
    import_advisories(osv_record(id: "DSA-1-1"))
    result = import_advisories(osv_record(id: "DSA-1-1", modified: "2026-10-22T00:00:00Z", withdrawn: "2026-10-22T00:00:00Z"))
    expect(Advisory.sole).to have_attributes(withdrawn_at: Time.utc(2026, 10, 22), withdrawn_reason: "withdrawn")
    expect(AdvisoryPackage.count).to eq(1)
    expect(result.import.counts).to include("withdrawn" => 1, "updated" => 1)
    expect(result.changed_packages).to eq("Debian:13" => [ "openssl" ])
  end

  it "replaces a stored advisory that stops naming the fleet's ecosystems, but skips new ones that never did" do
    import_advisories(osv_record(id: "DSA-1-1"))
    result = import_advisories(osv_record(id: "DSA-1-1", ecosystem: "Debian:12", modified: "2026-10-22T00:00:00Z"), osv_record(id: "DSA-2-1", ecosystem: "Debian:12"))
    expect(result.import.counts).to include("updated" => 1, "skipped" => 1)
    expect(Advisory.pluck(:advisory_id)).to eq([ "DSA-1-1" ])
    expect(AdvisoryPackage.count).to eq(0)
    expect(result.changed_packages).to eq("Debian:13" => [ "openssl" ])
  end

  describe "full imports" do
    before { import_advisories(osv_record(id: "DSA-1-1", package: "openssl"), osv_record(id: "DSA-2-1", package: "curl")) }

    it "mark advisories missing from the full data set as withdrawn (absent), and restore one that comes back" do
      result = import_advisories(osv_record(id: "DSA-1-1", package: "openssl"), full: true)
      expect(Advisory.find_by(advisory_id: "DSA-2-1")).to have_attributes(withdrawn_reason: "absent", withdrawn_at: be_present)
      expect(result.import.counts).to include("absent" => 1, "unchanged" => 1)
      expect(result.changed_packages).to eq("Debian:13" => [ "curl" ])

      back = import_advisories(osv_record(id: "DSA-1-1", package: "openssl"), osv_record(id: "DSA-2-1", package: "curl"), full: true)
      expect(Advisory.find_by(advisory_id: "DSA-2-1")).to have_attributes(withdrawn_reason: nil, withdrawn_at: nil)
      expect(back.import.counts).to include("updated" => 1, "absent" => 0)
    end

    it "do not mark anything absent when a record was malformed, or for ecosystems the import has nothing for" do
      import_advisories(osv_record(id: "DSA-1-1"), "broken", full: true)
      import_advisories(osv_record(id: "DSA-9-1", ecosystem: "Debian:12"), full: true)
      expect(Advisory.current.count).to eq(2)
    end

    it "count for freshness, and partial imports do not" do
      expect(Advisories::Freshness.statuses.sole).to be_never
      import_advisories(osv_record(id: "DSA-1-1"), full: true)
      expect(Advisories::Freshness.statuses.sole).to have_attributes(ecosystem: "Debian:13", updated_at: AdvisoryImport.last.finished_at, stale: false)
    end
  end

  describe "input that cannot be imported at all" do
    it "imports nothing from an unreadable archive" do
      path = osv_directory.join("all.zip")
      path.write("PK\x03\x04 not really a zip")
      expect { import(path) }.to raise_error(Advisories::Unreadable, "all.zip is not a readable zip archive")
      expect(Advisory.count).to eq(0)
    end

    it "rolls back every record when the archive breaks a limit part way through" do
      stub_const("Advisories::Reader::MAX_TOTAL_BYTES", 300)
      zip = osv_zip("a.json" => osv_record(id: "DSA-1-1"), "b.json" => osv_record(id: "DSA-2-1"), "c.json" => osv_record(id: "DSA-3-1"))
      expect { import(zip) }.to raise_error(Advisories::Unreadable, "all.zip holds more than 0 GiB of JSON")
      expect([ Advisory.count, AdvisoryImport.count, AuditEntry.count ]).to eq([ 0, 0, 0 ])
    end

    it "records the failure, audited, when the caller reports it" do
      import = described_class.record_failure(origin: "file", source: "all.zip", reason: "all.zip is not a readable zip archive")
      expect(import).to have_attributes(state: "failed", reason: "all.zip is not a readable zip archive", ecosystems: [])
      expect(AuditEntry.sole).to have_attributes(action: "advisory.import_failed", actor_type: "system",
                                                 changeset: { "origin" => "file", "source" => "all.zip", "reason" => "all.zip is not a readable zip archive" })
    end
  end

  it "serialises concurrent imports with a transaction lock" do
    sql = []
    callback = ->(*, payload) { sql << payload[:sql] }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { import_advisories(osv_record(id: "DSA-1-1")) }
    expect(sql.first(3).join).to include("pg_advisory_xact_lock")
  end
end
