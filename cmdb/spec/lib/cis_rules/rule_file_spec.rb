require "rails_helper"

# Parsing and validating rule files (P2-S04, DEC-12).
RSpec.describe CisRules::RuleFile do
  def rule(**overrides)
    { "key" => "ssh-root-login-off", "reference" => "CIS Debian 13 5.1.20", "title" => "SSH does not let root log in", "severity" => "high",
      "applies_to" => [ { "distribution" => "debian", "versions" => [ "13" ] } ], "fact" => "sshd.permitrootlogin",
      "condition" => { "eq" => "no" }, "remediation" => "Set PermitRootLogin to no." }.merge(overrides.transform_keys(&:to_s))
  end

  def file(*rules) = { "format_version" => 1, "rules" => rules }.to_yaml

  def errors(text) = described_class.parse(text).errors

  def condition_errors(fact, condition) = errors(file(rule(fact:, condition:)))

  it "parses a valid file into definitions, and enabled only where the file states it" do
    parsed = described_class.parse(file(rule, rule(key: "b", enabled: false), rule(key: "c", enabled: true)))
    expect(parsed).to be_valid
    expect(parsed.rules.map { |r| [ r.definition.key, r.enabled ] }).to eq([ [ "ssh-root-login-off", nil ], [ "b", false ], [ "c", true ] ])
    expect(parsed.rules.first.definition.fields).to eq(rule.except("key"))
  end

  it "reports every problem in the file at once, with a pointer to each, and keeps no rules (P2-S04)" do
    text = file(rule(severity: "urgent"), rule(key: "dup"), rule(key: "dup"), rule(key: "x", fact: "nope.fact"),
                rule(key: "y", fact: "sshd.maxauthtries", condition: { "matches" => "a+" }), rule(key: "z", condition: { "eq" => false }))
    parsed = described_class.parse(text)
    expect(parsed.rules).to eq([])
    expect(parsed.errors).to contain_exactly(
      "/rules/0/severity: is not one of: [\"low\", \"medium\", \"high\", \"critical\"]",
      "/rules/2/key: dup is already used by /rules/1",
      "/rules/3/fact: nope.fact is not in the fact manifest",
      "/rules/4/condition: matches works only on a string or list fact, and sshd.maxauthtries is integer",
      "/rules/5/condition: eq needs a string (quote yes, no, on, and off in YAML, or they are read as true and false)"
    )
  end

  it "catches the YAML trap of an unquoted no" do
    expect(errors(<<~YAML)).to eq([ "/rules/0/condition: eq needs a string (quote yes, no, on, and off in YAML, or they are read as true and false)" ])
      format_version: 1
      rules:
        - { key: a, reference: x, title: t, severity: low, applies_to: [{ distribution: debian }], fact: sshd.permitrootlogin, condition: { eq: no }, remediation: r }
    YAML
  end

  it "reads JSON too, since it is YAML" do
    expect(described_class.parse({ "format_version" => 1, "rules" => [ rule ] }.to_json)).to be_valid
  end

  it "refuses anything but plain data: objects, aliases, dates, NaN, non-UTF-8, a large file, and an empty one" do
    expect(errors("--- !ruby/object:OpenStruct\na: 1\n").first).to start_with("/: is not a plain YAML or JSON document")
    expect(errors("a: &x 1\nb: *x\n").first).to start_with("/: is not a plain YAML or JSON document (Alias")
    expect(errors("a: 2026-01-01\n").first).to include("Date")
    expect(errors("a: .nan\n")).to eq([ "/: holds a value JSON cannot represent, such as NaN or infinity" ])
    expect(errors("a: \"\xff\"".b)).to eq([ "/: is not UTF-8 text" ])
    expect(errors("#" * (1.megabyte + 1))).to eq([ "/: is larger than 1 MiB" ])
    expect(errors("")).to eq([ "/: is not an object" ])
  end

  it "lists at most 200 problems" do
    expect(errors(file(*Array.new(250) { |i| rule(key: "r#{i}", severity: "bad") })).size).to eq(200)
  end

  it "checks the rule shape before the manifest, and only for rules whose shape is right" do
    expect(errors(file(rule(fact: "nope.fact", condition: { "eq" => "no", "ne" => "yes" })))).to eq([ "/rules/0/condition: does not match exactly one `oneOf` schema" ])
  end

  it "is checked against the manifest it is given" do
    manifest = ConfigManifest::Manifest.new(version: 1, facts: [])
    expect(described_class.parse(file(rule), manifest:).errors).to eq([ "/rules/0/fact: sshd.permitrootlogin is not in the fact manifest" ])
  end
end
