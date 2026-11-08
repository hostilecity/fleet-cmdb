require "rails_helper"

# Reading the Debian Security Tracker's one JSON document a source package at a time (P2-S16): bounded memory and
# nesting, and the same result as parsing the whole document. Peak memory at the real file's size is measured by
# script/measure_debian_triage.rb (cmdb/README.md), not here.
RSpec.describe DebianTriage::Reader do
  def read(document, **) = described_class.new(document.is_a?(Pathname) ? document : tracker_file(document), **).to_a

  it "yields each source package with its entries, as JSON.parse of the whole document would" do
    packages = read(DebianTrackerHelpers::FIXTURES.join("sample.json"))
    expect(packages.map(&:package)).to eq([ "glibc", "openssl", "Not A Package" ])
    expect(packages.to_h { |p| [ p.package, p.entries ] }).to eq(JSON.parse(DebianTrackerHelpers::FIXTURES.join("sample.json").read))
    expect(packages.first.entries["CVE-2026-90010"]["description"]).to eq('made-up: braces { } [ ] and an escaped "quote" and backslash \\ in a string')
  end

  it "reads a generated document in the real file's shape across many chunks, compacting its buffer" do
    stub_const("#{described_class}::CHUNK", 4.kilobytes)
    stub_const("#{described_class}::COMPACT_AT", 16.kilobytes)
    path = tracker_file("")
    path.open("wb") { |io| DebianTrackerDocument.write(io, packages: 60, entries: 400) }
    packages = read(path)
    expect(packages.size).to eq(60)
    expect(packages.sum { |p| p.entries.size }).to eq(400)
    expect(packages.to_h { |p| [ p.package, p.entries ] }).to eq(JSON.parse(path.read))
  end

  it "reads an empty document and whitespace anywhere between tokens" do
    expect(read(" { } \n")).to eq([])
    expect(read(%( {\n "a" : {"CVE-2026-1": {"releases": {}}} ,\n "b":{} }\n)).map(&:package)).to eq(%w[a b])
  end

  it "yields a package whose value is not an object, not valid JSON, or nested too deep with its problem" do
    packages = read(%({"a": 1, "b": "x", "c": [1], "d": {"x": tru}, "e": {"1": {"2": {"3": {"4": {"5": {"6": {}}}}}}}, "f": {"x": [{"y": {"z": {}}}]}}))
    expect(packages.to_h { |p| [ p.package, p.problem ] }).to eq("a" => "is not an object", "b" => "is not an object", "c" => "is not an object",
                                                                  "d" => "is not valid JSON", "e" => "is nested more than 5 levels deep", "f" => nil)
  end

  {
    "a truncated document" => [ %({"a": {"CVE-2026-1": {"releases": {), "ends in the middle of the document" ],
    "a document cut inside a string" => [ %({"a": {"CVE-2026-1": "abc), "ends in the middle of the document" ],
    "a document cut after a backslash" => [ %({"a": {"x": "abc\\), "ends in the middle of the document" ],
    "a document cut after a key" => [ %({"a"), "ends in the middle of the document" ],
    "a document that is not an object" => [ %(["a"]), %(has "[" where "{" belongs) ],
    "a key that is not a string" => [ %({a: {}}), %(has "a" where "\\"" belongs) ],
    "a key that is not valid JSON" => [ %({"\\q": {}}), "has a source package name that is not a valid JSON string" ],
    "a missing colon" => [ %({"a" {}}), %(has "{" where ":" belongs) ],
    "a missing comma" => [ %({"a": {} "b": {}}), %(has "\\"" where a comma or the end of the document belongs) ],
    "data after the end" => [ %({"a": {}} {}), "has data after the end of the document" ]
  }.each do |problem, (document, message)|
    it "refuses #{problem}" do
      expect { read(document) }.to raise_error(Advisories::Unreadable, "json #{message}, so nothing was imported")
    end
  end

  it "refuses a source package larger than the limit, inside its value or in the space after it" do
    stub_const("#{described_class}::MAX_PACKAGE_BYTES", 64)
    stub_const("#{described_class}::CHUNK", 16)
    message = "json has a source package larger than 0 MiB, so nothing was imported"
    expect { read(%({"a": {"x": "#{'y' * 100}"}})) }.to raise_error(Advisories::Unreadable, message)
    expect { read(%({"a": {}, #{' ' * 100}"b": {}})) }.to raise_error(Advisories::Unreadable, message)
  end

  it "refuses a file larger than the download limit, or a path that is not a file" do
    expect { read(%({"a": {}}), max_bytes: 4) }.to raise_error(Advisories::Unreadable, "json is larger than 0 MiB")
    expect { described_class.new("/nonexistent/json").to_a }.to raise_error(Advisories::Unreadable, "json is not a file")
    expect(described_class.new("/nonexistent/json", name: "tracker").each).to be_an(Enumerator)
  end
end
