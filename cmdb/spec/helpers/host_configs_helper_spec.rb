require "rails_helper"

# Rule conditions in words, and the packages tile (P2-D02).
RSpec.describe HostConfigsHelper, type: :helper do
  it "says every operator and combinator in words, by the type of value it sees" do
    words = {
      { "eq" => false } => "equals false",
      { "ne" => "yes" } => %(does not equal "yes"),
      { "in" => %w[a b] } => %(is one of "a", "b"),
      { "not_in" => %w[a] } => %(is none of "a"),
      { "gte" => 14 } => "at least 14",
      { "lte" => 4 } => "at most 4",
      { "matches" => "aes.*" } => %(matches "aes.*"),
      { "mode_at_most" => "0640" } => "mode at most 0640",
      { "any" => [ { "eq" => 1 }, { "eq" => 2 } ] } => "equals 1 or equals 2",
      { "not" => { "eq" => "<b>" } } => %(not (equals "<b>"))
    }
    expect(words.keys.map { |condition| helper.expected_words(condition, "string") }).to eq(words.values)
    expect(helper.expected_words({ "matches" => "aes.*" }, "string_list")).to eq(%(every entry matches "aes.*"))
    expect(helper.expected_words({ "in" => %w[root] }, "string_list")).to eq(%(contains only "root"))
    expect(helper.expected_words([ { "present" => true }, { "field" => "active", "eq" => "active" } ], "service_state")).to eq(%(is installed, active equals "active"))
    expect(helper.expected_words({ "absent" => true }, "service_state")).to eq("is not installed")
    expect([ helper.expected_words({ "present" => true }, "file_attributes"), helper.expected_words({ "absent" => true }, "file_attributes") ]).to eq([ "exists", "does not exist" ])
  end

  describe "the packages tile" do
    def summary(set, changed_at = nil) = Struct.new(:package_set, :packages_changed_at).new(set, changed_at)

    it "names the manager and when the set last changed, or why there is no count" do
      dpkg = HostPackageSet.new(manager: "dpkg")
      expect(helper.package_tile_detail(summary(dpkg, 1.day.ago))).to eq("dpkg, set last changed 1 day ago")
      expect(helper.package_tile_detail(summary(dpkg))).to eq("dpkg")
      expect(helper.package_tile_detail(summary(HostPackageSet.new(manager: "unsupported")))).to eq("Unsupported package manager")
      expect(helper.package_tile_detail(summary(nil))).to eq("No package report yet")
    end
  end
end
