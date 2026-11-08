require "rails_helper"

# The severity rule (DEC-11, P2-S10): normalised to critical, high, medium, low, or unknown, keeping the raw value.
RSpec.describe Advisories::Severity do
  def severity_of(data) = described_class.of(data, Array(data["affected"]))

  describe Advisories::Cvss3 do
    {
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" => 9.8,
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" => 10.0,
      "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" => 6.5,
      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" => 7.8,
      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" => 3.1,
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" => 6.1,
      "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N" => 0.0
    }.each do |vector, score|
      it("scores #{vector} as #{score}, as FIRST's calculator does") { expect(described_class.base_score(vector)).to eq(score) }
    end

    it "returns nil for anything that is not a complete v3 base vector" do
      [ nil, 9.8, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "AV:N/AC:L/Au:N/C:P/I:P/A:P",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A" ].each do |vector| # the last, a metric without a value (review of #103)
        expect(described_class.base_score(vector)).to be_nil
      end
    end

    it "rounds up on integers, so floating point error never adds a tenth" do
      expect(described_class.roundup(4.000000001)).to eq(4.0)
      expect(described_class.roundup(4.02)).to eq(4.1)
    end
  end

  it "bands a CVSS v3 score, from the record or else from an affected entry, and keeps the vector" do
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    expect(severity_of("severity" => [ { "type" => "CVSS_V3", "score" => vector } ])).to have_attributes(level: "critical", raw: vector)
    { "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" => "high", "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" => "medium",
      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" => "low", "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N" => "low" }.each do |v, level|
      expect(severity_of("affected" => [ { "severity" => [ { "type" => "CVSS_V3", "score" => v } ] } ]).level).to eq(level)
    end
  end

  it "uses database_specific.severity words, then a Debian urgency, then unknown" do
    expect(severity_of("database_specific" => { "severity" => "MODERATE" })).to have_attributes(level: "medium", raw: "database_specific.severity: MODERATE")
    expect(severity_of("database_specific" => { "severity" => "Critical" }).level).to eq("critical")
    expect(severity_of("affected" => [ { "ecosystem_specific" => { "urgency" => "high" } } ])).to have_attributes(level: "high", raw: "urgency: high")
    expect(severity_of("affected" => [ { "ecosystem_specific" => { "urgency" => "unimportant" } } ]).level).to eq("low")
    expect(severity_of("database_specific" => { "urgency" => "medium*" }).level).to eq("medium")
    expect(severity_of("database_specific" => { "urgency" => "not yet assigned" })).to have_attributes(level: "unknown", raw: "urgency: not yet assigned")
    expect(severity_of({})).to have_attributes(level: "unknown", raw: nil)
  end

  it "ignores database_specific and ecosystem_specific that are not objects (review of #103)" do
    expect(severity_of("database_specific" => "HIGH")).to have_attributes(level: "unknown")
    expect(severity_of("affected" => [ { "ecosystem_specific" => "high" } ], "database_specific" => [ "x" ]).level).to eq("unknown")
  end

  it "keeps a v2 or v4 vector as the raw value without scoring it, and prefers a v3 vector to any word" do
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    expect(severity_of("severity" => [ { "type" => "CVSS_V4", "score" => v4 } ])).to have_attributes(level: "unknown", raw: v4)
    v3 = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"
    expect(severity_of("severity" => [ { "type" => "CVSS_V4", "score" => v4 }, { "type" => "CVSS_V3", "score" => v3 } ],
                       "database_specific" => { "severity" => "HIGH" })).to have_attributes(level: "low", raw: v3)
    expect(severity_of("severity" => "high", "database_specific" => { "severity" => "extreme" }).level).to eq("unknown")
  end
end
