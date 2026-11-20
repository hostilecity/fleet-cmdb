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
                    kev_vulnerability("CVE-2026-0005", due_date: nil, vendorProject: "Evil\u0000 <b>Corp</b>#{'x' * 200}", product: 12))
    catalog = described_class.new(path).read
    expect(catalog.entries.map(&:cve_id)).to eq(%w[CVE-2026-0001 CVE-2026-0005])
    expect(catalog.entries.first.date_added).to eq(Date.new(2026, 11, 2))
    expect(catalog.entries.last).to have_attributes(due_date: nil, product: nil)
    expect(catalog.entries.last.vendor).to start_with("Evil <b>Corp</b>xxx").and(have_attributes(length: 128))
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
end
