require "rails_helper"

RSpec.describe PackageVersions do
  let(:dpkg) { PackageVersions::Dpkg }

  describe "conformance with dpkg --compare-versions (P2-S09, FR-2.4)" do
    corpus = Rails.root.join("spec/fixtures/dpkg/compare-versions.tsv").readlines(chomp: true).reject { |l| l.start_with?("#") || l.empty? }
    rows = corpus.map { |line| line.split("\t", -1) }

    it "has at least 200 pairs, each with a result from dpkg" do
      expect(rows.size).to be >= 200
      expect(rows.map(&:last).uniq).to contain_exactly("-1", "0", "1", "invalid")
    end

    it "agrees with dpkg on every pair, and in both directions" do
      disagreements = rows.filter_map do |left, right, expected|
        want = expected == "invalid" ? :invalid : Integer(expected)
        got = [ dpkg.compare(left, right), dpkg.compare(right, left) ]
        mirror = want == :invalid ? :invalid : -want
        "#{left} vs #{right}: want #{want}, got #{got.inspect}" unless got == [ want, mirror ]
      end
      expect(disagreements).to eq([])
    end
  end

  describe "known tricky cases" do
    {
      "epochs outrank everything else" => [ "1:0.1", "99.9", 1 ],
      "a zero epoch is the same as none" => [ "0:1.0", "1.0", 0 ],
      "a tilde sorts before the end" => [ "1.0~rc1", "1.0", -1 ],
      "two tildes sort before one" => [ "1.0~~", "1.0~", -1 ],
      "a backport sorts before its source" => [ "1.0-1~bpo13+1", "1.0-1", -1 ],
      "leading zeros are ignored" => [ "1.002", "1.2", 0 ],
      "numbers compare as numbers" => [ "1.10", "1.9", 1 ],
      "stable updates order numerically" => [ "1.0-1+deb13u10", "1.0-1+deb13u9", 1 ],
      "a stable update follows its revision" => [ "1.0-1+deb13u1", "1.0-1", 1 ],
      "an alpha suffix follows the bare version" => [ "1.0a", "1.0", 1 ],
      "letters sort before other symbols" => [ "1.0a", "1.0+", -1 ],
      "a missing revision equals revision 0" => [ "1.0", "1.0-0", 0 ],
      "the last hyphen starts the revision" => [ "1.0-1-1", "1.0-1-2", -1 ]
    }.each do |name, (left, right, expected)|
      it(name) { expect(dpkg.compare(left, right)).to eq(expected) }
    end

    it "does what string comparison gets wrong" do
      expect([ "1.10" <=> "1.9", dpkg.compare("1.10", "1.9") ]).to eq([ -1, 1 ])
    end
  end

  describe "parsing" do
    it "splits epoch, upstream, and revision, and prints a version as dpkg does" do
      expect(dpkg.parse("2:9.1.1230-2+deb13u1")).to eq(PackageVersions::Dpkg::Version.new(epoch: 2, upstream: "9.1.1230", revision: "2+deb13u1"))
      expect(dpkg.parse("0:1.0").to_s).to eq("1.0")
      expect(dpkg.parse("1:1.0-1").to_s).to eq("1:1.0-1")
    end

    it "trims surrounding whitespace as dpkg does" do
      expect(dpkg.compare(" 1.0\t", "1.0")).to eq(0)
    end

    it "gives dpkg's reason for each version it refuses" do
      {
        "1.0 1" => "version string has embedded spaces", "  " => "version string is empty", "1:" => "nothing after colon in version number",
        ":1" => "epoch in version is empty", "1a:1" => "epoch in version is not number", "-1:1" => "epoch in version is negative",
        "2147483648:1" => "epoch in version is too big", "1.0-" => "revision number is empty", "1:-1" => "version number is empty"
      }.each do |text, reason|
        expect(dpkg.parse(text)).to eq(PackageVersions::Invalid.new(version: text, reason:)), text
      end
    end

    it "refuses what it deliberately does not take from dpkg: an empty string, non-ASCII text, and non-strings" do
      expect([ "", "1.0é", nil, 1 ].map { |v| dpkg.parse(v).reason })
        .to eq([ "version string is empty", "version string is not ASCII", "version is not a string", "version is not a string" ])
      expect([ dpkg.valid?("1.0"), dpkg.valid?("1.0é") ]).to eq([ true, false ])
    end

    it "compares parsed versions as well as strings, and reports invalid rather than guessing" do
      expect(dpkg.compare(dpkg.parse("1.0"), "1.1")).to eq(-1)
      expect([ dpkg.compare("1.0", "1:"), dpkg.compare("", "1.0"), dpkg.compare(nil, nil) ]).to all(eq(:invalid))
    end
  end

  describe ".sort" do
    it "sorts by dpkg order, then puts invalid versions last, both in input order" do
      expect(described_class.sort(%w[2.0 1:0.1 bad:x 1.0~rc1 1.0 01.0 1.0-], scheme: "dpkg"))
        .to eq(%w[1.0~rc1 1.0 01.0 2.0 1:0.1 bad:x 1.0-])
    end

    it "never raises on a mixed list" do
      junk = [ nil, "", " ", "1:", ":", "~", "-", "é", 7, "1.0", "1:1.0", "1.0~", "a", "+1:1", "0" ]
      rng = Random.new(19)
      20.times do
        list = Array.new(30) { junk.sample(random: rng) }
        expect { described_class.sort(list, scheme: PackageVersions::Dpkg) }.not_to raise_error
        expect(described_class.sort(list, scheme: "dpkg")).to match_array(list)
      end
    end
  end

  it "looks schemes up by package manager and has only dpkg (DEC-01)" do
    expect(described_class.for("dpkg")).to eq(PackageVersions::Dpkg)
    expect(PackageVersions::SCHEMES.keys).to eq([ "dpkg" ])
    expect { described_class.for("rpm") }.to raise_error(KeyError)
    expect(PackageVersions::Dpkg::MANAGER).to eq("dpkg")
  end
end
