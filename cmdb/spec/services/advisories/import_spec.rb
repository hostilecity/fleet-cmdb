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

  # VT-S04 (#257): the CVSS v3 vector's parts on each advisory, and a changed vector or severity handed to triage.
  it "stores the CVSS vector's parts, and hands a stored advisory whose vector or severity changed to the triage run" do
    vector = ->(v) { [ { "type" => "CVSS_V3", "score" => v } ] }
    import_advisories(osv_record(id: "DSA-1-1", severity: vector.("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
                      osv_record(id: "DSA-2-1", package: "curl", severity: [ { "type" => "CVSS_V4", "score" => "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" } ]),
                      osv_record(id: "DSA-3-1", package: "zlib", severity: vector.("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")))
    expect(Advisory.order(:advisory_id).pluck(:advisory_id, :cvss_av, :cvss_pr, :cvss_ui))
      .to eq([ [ "DSA-1-1", "N", "N", "N" ], [ "DSA-2-1", nil, nil, nil ], [ "DSA-3-1", "L", "L", "N" ] ])
    expect(TriageSignalChange.count).to eq(0) # new advisories are triaged when their findings are matched

    import_advisories(osv_record(id: "DSA-1-1", modified: "2026-10-21T08:00:00Z", severity: vector.("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")),
                      osv_record(id: "DSA-2-1", package: "curl", modified: "2026-10-21T08:00:00Z", summary: "only the summary changed",
                                 severity: [ { "type" => "CVSS_V4", "score" => "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" } ]),
                      osv_record(id: "DSA-3-1", package: "zlib", modified: "2026-10-21T08:00:00Z"))
    changed = Advisory.where(advisory_id: %w[DSA-1-1 DSA-3-1]).pluck(:id).sort
    expect(TriageSignalChange.where(kind: "advisory").pluck(:advisory_id).sort).to eq(changed)
    expect(Advisory.find_by!(advisory_id: "DSA-3-1")).to have_attributes(cvss_av: nil, severity: "unknown")
  end

  it "hands over a vector change that leaves the severity the same (review of #269)" do
    vector = ->(v) { [ { "type" => "CVSS_V3", "score" => v } ] }
    import_advisories(osv_record(id: "DSA-1-1", severity: vector.("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"))) # 8.8 high
    import_advisories(osv_record(id: "DSA-1-1", modified: "2026-10-21T08:00:00Z", severity: vector.("CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"))) # 8.0 high
    expect(Advisory.sole).to have_attributes(severity: "high", cvss_av: "A")
    expect(TriageSignalChange.where(kind: "advisory").pluck(:advisory_id)).to eq([ Advisory.sole.id ])
  end

  it "hands over an advisory whose CVE set gains or loses a CVE in KEV or in the EPSS high band, and no other alias change" do
    import_kev(kev_file("CVE-2026-0010"))
    EpssScore.create!(cve_id: "CVE-2026-0020", score: 0.5, percentile: 0.9, band: "high", score_date: Date.current)
    EpssScore.create!(cve_id: "CVE-2026-0030", score: 0.01, percentile: 0.1, band: "normal", score_date: Date.current)
    import_advisories(osv_record(id: "DSA-1-1"), osv_record(id: "DSA-2-1", package: "curl", aliases: %w[CVE-2026-0020]),
                      osv_record(id: "DSA-3-1", package: "zlib"))
    TriageSignalChange.delete_all
    later = "2026-10-21T08:00:00Z"
    import_advisories(osv_record(id: "DSA-1-1", modified: later, aliases: %w[CVE-2026-0010]), # gains a KEV CVE
                      osv_record(id: "DSA-2-1", package: "curl", modified: later), # loses an EPSS-high CVE
                      osv_record(id: "DSA-3-1", package: "zlib", modified: later, aliases: %w[CVE-2026-0030 CVE-2026-0040])) # neither
    expect(TriageSignalChange.where(kind: "advisory").pluck(:advisory_id).sort).to eq(Advisory.where(advisory_id: %w[DSA-1-1 DSA-2-1]).pluck(:id).sort)
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

  it "reports a record of a shape the parser did not expect as malformed instead of rolling back the import (review of #103)" do
    allow(Advisories::Severity).to receive(:of).and_call_original
    allow(Advisories::Severity).to receive(:of).with(hash_including("id" => "DSA-2-1"), anything).and_raise(NoMethodError, "undefined method")
    result = import_advisories(osv_record(id: "DSA-1-1"), osv_record(id: "DSA-2-1"))
    expect(Advisory.pluck(:advisory_id)).to eq([ "DSA-1-1" ])
    expect(result.import.problems).to eq([ { "location" => "DSA-2-1.json", "id" => "DSA-2-1", "problem" => "could not be read (NoMethodError)" } ])
  end

  it "imports records whose free-form severity fields have unexpected shapes, with an unknown severity (review of #103)" do
    result = import_advisories(osv_record(id: "DSA-1-1", database_specific: "HIGH"),
                               osv_record(id: "DSA-2-1", severity: [ { "type" => "CVSS_V3", "score" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A" } ]),
                               osv_record(id: "DSA-3-1").tap { |r| r["affected"][0]["ecosystem_specific"] = "high" })
    expect(result.import.counts).to include("created" => 3, "malformed" => 0)
    expect(Advisory.pluck(:severity).uniq).to eq([ "unknown" ])
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

  # The withdrawal guard is off here, for the absence sweep itself; import_bounds_spec.rb covers the guard.
  describe "full imports", withdrawal_guard: { share: 1.0, min_records: 0 } do
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

    it "do not mark absent an advisory newer than everything in the data set, as an older archive would (review of #103)" do
      import_advisories(osv_record(id: "DSA-3-1", modified: "2026-10-25T00:00:00Z"))
      result = import_advisories(osv_record(id: "DSA-1-1", package: "openssl"), full: true) # an archive from 2026-10-20
      expect(Advisory.find_by(advisory_id: "DSA-3-1")).to have_attributes(withdrawn_reason: nil)
      expect(Advisory.find_by(advisory_id: "DSA-2-1")).to have_attributes(withdrawn_reason: "absent") # as old as the archive
      expect(result.import.counts["absent"]).to eq(1)
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
