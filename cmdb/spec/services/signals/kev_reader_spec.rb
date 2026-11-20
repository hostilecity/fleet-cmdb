require "rails_helper"

# Reading CISA's KEV catalog (VT-S02): only the fields the triage uses, validated and cleaned; a file that is not the
# catalog imports nothing.
RSpec.describe Signals::KevReader do
  it "reads the recorded catalog: version, count, and the kept fields of each entry" do
    catalog = described_class.new(SignalHelpers::SIGNAL_FIXTURES.join("known_exploited_vulnerabilities.json")).read
    expect(catalog).to have_attributes(version: "2026.11.19", count: 3, malformed: 0, repeated: 0, problems: [])
    expect(catalog.entries.first).to have_attributes(cve_id: "CVE-2026-90777", date_added: Date.new(2026, 11, 2), due_date: Date.new(2026, 11, 23),
                                                     known_ransomware: true, vendor: "OpenBSD", product: "OpenSSH")
    expect(catalog.entries.map(&:known_ransomware)).to eq([ true, false, false ])
  end

  it "skips and counts malformed entries with why, keeps the first of a repeated CVE, and cleans and caps text" do
    stub_const("Signals::KevReader::PROBLEM_LIMIT", 4)
    path = kev_file("CVE-2026-0001", kev_vulnerability("CVE-2026-0001", date_added: "2026-01-01"), 5, kev_vulnerability("CVE-2026"),
                    kev_vulnerability("CVE-2026-0002", date_added: "2026-13-45"), kev_vulnerability("CVE-2026-0003", date_added: nil),
                    kev_vulnerability("CVE-2026-0004", due_date: 5),
                    kev_vulnerability("CVE-2026-0005", due_date: nil, vendorProject: "Evil\u0000 <b>Corp</b>#{'x' * 200}", product: 12),
                    *(1..60).map { |i| format("CVE-2025-%04d", i) }) # enough valid entries that the malformed ones stay under 10% of the count
    catalog = described_class.new(path).read
    expect(catalog.entries.map(&:cve_id).first(2)).to eq(%w[CVE-2026-0001 CVE-2026-0005])
    expect(catalog.entries.first.date_added).to eq(Date.new(2026, 11, 2))
    expect(catalog.entries.second).to have_attributes(due_date: nil, product: nil)
    expect(catalog.entries.second.vendor).to start_with("Evil <b>Corp</b>xxx").and(have_attributes(length: 128))
    expect(catalog).to have_attributes(malformed: 5, repeated: 1)
    expect(catalog.problems).to eq([ { "index" => 2, "problem" => "is not an object" }, { "index" => 3, "problem" => "has no valid cveID" },
                                     { "index" => 4, "id" => "CVE-2026-0002", "problem" => "has no valid dateAdded" },
                                     { "index" => 5, "id" => "CVE-2026-0003", "problem" => "has no valid dateAdded" } ])
  end

  it "keeps no version or count that is not in the catalog's shape" do
    path = kev_file(raw: JSON.generate("catalogVersion" => "<script>", "count" => "3", "vulnerabilities" => [ kev_vulnerability("CVE-2026-0001") ]))
    expect(described_class.new(path).read).to have_attributes(version: nil, count: nil)
  end

  it "refuses a file that is not a KEV catalog, naming the file, so nothing is imported" do
    {
      "is not valid JSON" => "{", "is not valid UTF-8" => "\xff\xfe".b, "is not a KEV catalog (no vulnerabilities list)" => "[]",
      "lists no vulnerabilities" => '{"vulnerabilities": []}'
    }.each do |problem, raw|
      expect { described_class.new(kev_file(raw:), name: "kev.json").read }
        .to raise_error(Advisories::Unreadable, "kev.json #{problem}, so nothing was imported")
    end
    expect { described_class.new("/nonexistent/kev.json").read }.to raise_error(Advisories::Unreadable, "kev.json is not a file, so nothing was imported")
    expect { described_class.new(kev_file("CVE-2026-0001"), max_bytes: 10).read }.to raise_error(Advisories::Unreadable, /is larger than 0 MiB/)
  end

  # Review of #269: a catalog with no valid entry, or far fewer than its count, is a broken file; and the shape is
  # bounded before JSON.parse builds anything.
  it "refuses a catalog with no valid entry, or whose valid entries fall short of its count by more than 10%" do
    expect { described_class.new(kev_file(kev_vulnerability("CVE-1"), kev_vulnerability("bad")), name: "kev.json").read }
      .to raise_error(Advisories::Unreadable, "kev.json has no valid entry (2 malformed), so nothing was imported")
    ten = (1..10).map { |i| format("CVE-2026-%04d", i) }
    expect(described_class.new(kev_file(*ten.first(9), kev_vulnerability("CVE-x"))).read.entries.size).to eq(9) # 10% short is allowed
    expect { described_class.new(kev_file(*ten.first(8), kev_vulnerability("CVE-x"), kev_vulnerability("CVE-y"))).read }
      .to raise_error(Advisories::Unreadable, /has 8 valid entries of the 10 its count gives \(2 malformed\)/)
  end

  it "refuses too many entries, objects and arrays, or an entry too large, before parsing" do
    expect(JSON).not_to receive(:parse)
    stub_const("Signals::KevReader::MAX_ENTRIES", 2)
    expect { described_class.new(kev_file("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003")).read }.to raise_error(Advisories::Unreadable, /has more than 2 entries/)
    stub_const("Signals::KevReader::MAX_CONTAINERS", 3)
    expect { described_class.new(kev_file("CVE-2026-0001")).read }.to raise_error(Advisories::Unreadable, /has more than 3 objects and arrays/)
    stub_const("Signals::KevReader::MAX_CONTAINERS", 100)
    stub_const("Signals::KevReader::MAX_ENTRY_BYTES", 500)
    expect { described_class.new(kev_file(kev_vulnerability("CVE-2026-0001", notes: "x" * 600))).read }.to raise_error(Advisories::Unreadable, /has an entry larger than 0 KiB/)
    expect { described_class.new(kev_file(raw: '{"vulnerabilities": ["unterminated')).read }.to raise_error(Advisories::Unreadable, /is not valid JSON/)
  end

  it "does not count braces or escaped quotes inside strings" do
    stub_const("Signals::KevReader::MAX_CONTAINERS", 4)
    entry = kev_vulnerability("CVE-2026-0001", notes: '{[{[ "quoted \\" {braces}" ]}]}', cwes: "none")
    expect(described_class.new(kev_file(entry)).read.entries.map(&:cve_id)).to eq(%w[CVE-2026-0001])
  end

  # Re-review of #269: entries of any type count toward the cap before parsing, and a file ending in a backslash
  # inside a string is unreadable, not a crash.
  it "counts values of any type toward the entry cap before parsing" do
    expect(JSON).not_to receive(:parse)
    stub_const("Signals::KevReader::MAX_ENTRIES", 3)
    [ '{"vulnerabilities":[1,1,1,1]}', '{"vulnerabilities":["","","",""]}', '{"vulnerabilities":[null,null,null,null]}',
      '{"vulnerabilities":[1.5e300,1.5e300,1.5e300,1.5e300]}' ].each do |raw|
      expect { described_class.new(kev_file(raw:)).read }.to raise_error(Advisories::Unreadable, /has more than 3 entries/), raw
    end
  end

  it "reads a real-shaped catalog at the entry cap, commas inside entries and strings not counted" do
    stub_const("Signals::KevReader::MAX_ENTRIES", 3)
    entries = (1..3).map { |i| kev_vulnerability(format("CVE-2026-%04d", i), cwes: %w[CWE-1 CWE-2], notes: "a, b, c") }
    expect(described_class.new(kev_file(*entries)).read.entries.size).to eq(3)
  end

  it "refuses a file that ends after a backslash inside a string" do
    expect { described_class.new(kev_file(raw: '{"a":"\\'), name: "kev.json").read }.to raise_error(Advisories::Unreadable, "kev.json is not valid JSON, so nothing was imported")
  end
end
