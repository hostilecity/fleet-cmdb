require "rails_helper"

RSpec.describe AgentApi::AgentVersion do
  def v(string) = described_class.parse(string)

  it "orders versions by SemVer 2.0.0 precedence" do
    ordered = %w[0.0.9 0.1.0-alpha 0.1.0-alpha.1 0.1.0-alpha.beta 0.1.0-beta 0.1.0-beta.2 0.1.0-beta.11 0.1.0-rc.1 0.1.0 0.1.1 0.10.0 1.0.0]
    expect(ordered.map { |s| v(s) }.each_cons(2).all? { |a, b| a < b }).to be(true)
  end

  it "ignores build metadata" do
    expect(v("1.2.3+build.5")).to eq(v("1.2.3"))
  end

  it "rejects anything that is not a semantic version" do
    [ nil, "", "1.2", "01.2.3", "1.2.3.4", "v1.2.3", 7 ].each { |s| expect(v(s)).to be_nil }
  end
end

RSpec.describe AgentApi::Schema do
  it "reads schemas from docs/api" do
    expect(described_class.dir).to eq(Rails.root.join("../docs/api/schemas").expand_path)
    expect(described_class.latest_version).to eq(1)
    expect(described_class.exists?("enroll.request", 1)).to be(true)
    expect(described_class.exists?("enroll.request", 2)).to be(false)
    expect(described_class.exists?("enroll.request", "1")).to be(false)
  end

  it "finds undeclared keys at any depth as JSON Pointers" do
    data = {
      "schema_version" => 1, "extra" => 1,
      "os" => { "id" => "debian", "codename" => "trixie" },
      "disks" => [ { "mount" => "/", "inode/s" => 3 } ]
    }
    expect(described_class.undeclared_pointers("inventory.request", 1, data)).to eq([ "/extra", "/os/codename", "/disks/0/inode~1s" ])
  end

  it "reports problems without echoing values" do
    errors = described_class.errors("enroll.request", 1, { "token" => "EXAMPLE-sensitive-value" })
    expect(errors).to include(a_hash_including("pointer" => "/token"))
    expect(errors.to_json).not_to include("EXAMPLE-sensitive-value")
  end
end
