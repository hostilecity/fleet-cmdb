require "rails_helper"

# Validating and cleaning one OSV record (P2-S10, DEC-11, NFR-1).
RSpec.describe Advisories::Record do
  def parse(data) = described_class.parse(data.is_a?(String) ? data : JSON.generate(data))

  def fixture(name) = described_class.parse(AdvisoryHelpers::OSV_FIXTURES.join(name).binread)

  it "keeps the fleet's ecosystem from a Debian advisory, with its ranges, first fixed version, and aliases" do
    record = fixture("DSA-9001-1.json")
    expect(record).to have_attributes(advisory_id: "DSA-9001-1", summary: "openssl - security update", aliases: [ "CVE-2026-90001" ],
                                      severity: "critical", modified_at: Time.utc(2026, 10, 20, 8), published_at: Time.utc(2026, 10, 19, 12),
                                      withdrawn_at: nil, reference_url: "https://security-tracker.example.org/tracker/DSA-9001-1", rejected_urls: 0)
    expect(record.packages).to eq([ described_class::Package.new(ecosystem: "Debian:13", package: "openssl",
                                                                 ranges: [ [ { "introduced" => "0" }, { "fixed" => "3.5.1-1+deb13u1" } ] ],
                                                                 fixed_version: "3.5.1-1+deb13u1") ])
  end

  it "rejects reference URLs with other schemes and keeps the best http or https one" do
    record = fixture("DEBIAN-CVE-2026-90002.json")
    expect(record.reference_url).to eq("https://security-tracker.example.org/tracker/CVE-2026-90002")
    expect(record.rejected_urls).to eq(2) # javascript: and ftp:
    only_bad = parse(osv_record(references: [ { "type" => "ADVISORY", "url" => "javascript:alert(1)" }, { "type" => "WEB", "url" => "data:text/html,x" },
                                              { "type" => "WEB", "url" => "https://exa mple.org/" }, { "type" => "WEB", "url" => "http:///no-host" },
                                              { "type" => "WEB", "url" => "https://example.org/#{'a' * 2048}" }, { "type" => "WEB", "url" => 42 }, { "type" => "WEB", "url" => "https://[bad" } ]))
    expect(only_bad).to have_attributes(reference_url: nil, rejected_urls: 7)
    expect(parse(osv_record(references: [ { "type" => "WEB", "url" => "HTTP://example.org/a" } ])).reference_url).to eq("HTTP://example.org/a")
    expect(parse(osv_record(references: "nope"))).to have_attributes(reference_url: nil, rejected_urls: 0)
  end

  it "sanitises text: control characters removed, white space squashed, length capped; markup kept for escaping" do
    record = fixture("DEBIAN-CVE-2026-90002.json")
    expect(record.summary).to eq("In curl before 8.15.0, a crafted URL can cause <script>alert(1)</script> a crash.")
    expect(record).to have_attributes(severity: "medium", severity_raw: "urgency: medium", aliases: [ "CVE-2026-90002" ])
    long = parse(osv_record(summary: "x" * 600, aliases: [ "CVE-1", "bad alias", 7, "CVE-1" ]))
    expect(long.summary.length).to eq(512)
    expect(long.aliases).to eq([ "CVE-1" ])
    expect(parse(osv_record).summary).to be_nil
  end

  it "merges the ranges of affected entries naming the same package and ignores SEMVER and GIT ranges" do
    record = parse(osv_record.merge("affected" => [
      { "package" => { "ecosystem" => "Debian:13", "name" => "linux" }, "ranges" => [ { "type" => "ECOSYSTEM", "events" => [ { "introduced" => "6.12.1-1" }, { "fixed" => "6.12.9-1" } ] } ] },
      { "package" => { "ecosystem" => "Debian:13", "name" => "linux" }, "ranges" => [ { "type" => "GIT", "repo" => "https://example.org/linux.git", "events" => [ { "introduced" => "abc" } ] },
                                                                                       { "type" => "ECOSYSTEM", "events" => [ { "introduced" => "6.16.1-1" } ] } ] },
      { "package" => { "ecosystem" => "PyPI", "name" => "Not A Debian Name" } },
      { "package" => "not an object" }
    ]))
    expect(record.packages.sole).to have_attributes(package: "linux", fixed_version: "6.12.9-1",
                                                    ranges: [ [ { "introduced" => "6.12.1-1" }, { "fixed" => "6.12.9-1" } ], [ { "introduced" => "6.16.1-1" } ] ])
  end

  it "has no packages when nothing is for the fleet's ecosystems" do
    expect(fixture("DEBIAN-CVE-2026-90003.json").packages).to eq([])
    expect(parse(osv_record.except("affected")).packages).to eq([])
  end

  it "keeps a withdrawn advisory with its time" do
    expect(parse(osv_record(withdrawn: "2026-10-25T00:00:00Z"))).to be_withdrawn
  end

  {
    "is not valid JSON" => "{\"id\": ",
    "is not a JSON object" => "[1, 2]",
    "is not valid UTF-8" => "{\"id\": \"\xFF\"}",
    "has no valid id" => { "modified" => "2026-10-20T08:00:00Z" },
    "has no modified time" => { "id" => "DSA-1-1" },
    "has a modified time that is not RFC 3339" => { "id" => "DSA-1-1", "modified" => "yesterday" },
    "has a published time that is not RFC 3339" => { "id" => "DSA-1-1", "modified" => "2026-10-20T08:00:00Z", "published" => "2026-13-45T99:00:00Z" },
    "has an affected list that is not an array" => { "id" => "DSA-1-1", "modified" => "2026-10-20T08:00:00Z", "affected" => {} },
    "has affected[0] that is not an object" => { "id" => "DSA-1-1", "modified" => "2026-10-20T08:00:00Z", "affected" => [ 1 ] }
  }.each do |problem, data|
    it("refuses a record that #{problem}") { expect { parse(data) }.to raise_error(described_class::Malformed, problem) }
  end

  it "refuses invalid package names, ranges, and events in the fleet's ecosystems only" do
    bad = ->(entry) { osv_record.merge("affected" => [ { "package" => { "ecosystem" => "Debian:13", "name" => "openssl" } }.merge(entry) ]) }
    expect { parse(osv_record(package: "Bad Name")) }.to raise_error(described_class::Malformed, "has affected[0] with an invalid package name")
    expect { parse(bad.("ranges" => {})) }.to raise_error(described_class::Malformed, "has affected[0].ranges that is not an array")
    expect { parse(bad.("ranges" => [ 1 ])) }.to raise_error(described_class::Malformed, "has affected[0].ranges[0] that is not an object")
    expect { parse(bad.("ranges" => [ { "type" => "ECOSYSTEM", "events" => [] } ])) }.to raise_error(described_class::Malformed, "has affected[0].ranges[0] without events")
    [ [ { "introduced" => "0", "fixed" => "1" } ], [ { "introduced" => "has space" } ], [ { "bogus" => "1" } ], [ { "introduced" => 1 } ], [ "0" ] ].each do |events|
      expect { parse(bad.("ranges" => [ { "type" => "ECOSYSTEM", "events" => events } ])) }.to raise_error(described_class::Malformed, "has affected[0].ranges[0] with an invalid event")
    end
    expect { parse(bad.("ranges" => [ { "type" => "ECOSYSTEM", "events" => [ { "fixed" => "1.0" } ] } ])) }
      .to raise_error(described_class::Malformed, "has affected[0].ranges[0] without an introduced event")
    expect(parse(osv_record(ecosystem: "Debian:12", package: "Bad Name")).packages).to eq([])
  end

  it "keeps a version dpkg cannot parse: matching decides it is not evaluated (P2-S11)" do
    expect(parse(osv_record(fixed: "1:bad:")).packages.sole.fixed_version).to eq("1:bad:")
  end

  it "finds the id of a malformed document for the report, when it has one" do
    expect(described_class.id_of({ "id" => "DSA-1-1" })).to eq("DSA-1-1")
    expect(described_class.id_of({ "id" => "../../etc" })).to be_nil
    expect(described_class.id_of([])).to be_nil
  end
end
