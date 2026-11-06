# Guards the CIS-aligned rule file format in docs/api/rules (P2-S04, DEC-12): the schema, its examples, and that
# every operator, combinator, and property appears in a valid example the server also accepts.
require "rails_helper"

RSpec.describe "Rule file format (docs/api/rules)" do
  root = Rails.root.join("../docs/api/rules/v1")
  examples = root.glob("examples/{valid,invalid}/*.json").sort.map { |path| [ path.parent.basename.to_s, path ] }
  let(:schema) { JSON.parse(CisRules::SCHEMA_PATH.read) }

  def keys_in(value, out = Set.new)
    case value
    when Hash then value.each { |key, sub| keys_in(sub, out << key) }
    when Array then value.each { |sub| keys_in(sub, out) }
    end
    out
  end

  it "is a valid draft 2020-12 schema, read from where the server reads it" do
    expect(CisRules::SCHEMA_PATH).to eq(root.join("cis-rules.schema.json").expand_path)
    expect(schema["$schema"]).to eq("https://json-schema.org/draft/2020-12/schema")
    expect(JSONSchemer.validate_schema(schema).map { |e| e.fetch("error") }).to eq([])
  end

  it "has valid and invalid examples" do
    expect(examples.map(&:first).uniq).to contain_exactly("valid", "invalid")
  end

  examples.each do |kind, path|
    it "#{kind}/#{path.basename} #{kind == 'valid' ? 'validates and parses with no problems' : 'is rejected by the schema'}" do
      data = JSON.parse(path.read)
      if kind == "valid"
        expect(CisRules.schemer.validate(data).map { |e| e.fetch("error") }).to eq([])
        expect(CisRules::RuleFile.parse(path.read).errors).to eq([])
      else
        expect(CisRules.schemer.valid?(data)).to be(false)
        expect(CisRules::RuleFile.parse(path.read).errors).not_to be_empty
      end
    end
  end

  it "uses every operator, combinator, and property in a valid example" do
    used = examples.select { |kind, _| kind == "valid" }.map { |_, path| keys_in(JSON.parse(path.read)) }.reduce(Set.new, :|)
    declared = %w[rule platform condition].flat_map { |name| schema.dig("$defs", name, "properties").keys } + schema["properties"].keys
    expect(declared.uniq.sort - used.to_a).to eq([])
    expect(CisRules::Condition::OPERATORS + CisRules::Condition::COMBINATORS).to match_array(schema.dig("$defs", "condition", "properties").keys - [ "field" ])
  end

  it "lists the same severities and fields as the server" do
    expect(schema.dig("$defs", "rule", "properties", "severity", "enum")).to eq(CisRules::SEVERITIES)
    expect(schema.dig("$defs", "condition", "properties", "field", "enum")).to match_array(CisRules::Condition::FIELDS.values.flatten)
    expect(schema.dig("properties", "format_version", "const")).to eq(CisRules::FORMAT_VERSION)
  end
end
