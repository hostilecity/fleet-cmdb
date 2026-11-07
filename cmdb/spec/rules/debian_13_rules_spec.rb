require "rails_helper"

# The starter CIS-aligned rule set for Debian 13 (P2-CIS-RULES, FR-2.2, DEC-10): it validates and imports, and
# every rule passes and fails on hand-chosen values (spec/fixtures/cis_rules/debian-13.yml).
RSpec.describe "Starter rules: config/rules/debian-13.yml" do
  path = Rails.root.join("config/rules/debian-13.yml")
  file = CisRules::RuleFile.parse(path.read)
  fixtures = YAML.safe_load_file(Rails.root.join("spec/fixtures/cis_rules/debian-13.yml"), permitted_classes: [], aliases: false)
  debian13 = { "id" => "debian", "version_id" => "13" }

  def facts(rule, value) = { rule.fact => { "state" => "ok", "value" => value, "reason" => nil } }

  it "validates as a whole" do
    expect(file.errors).to eq([])
    expect(file.rules.size).to be >= 60
  end

  it "imports, enabled, and imports again with no new version" do
    first = CisRules::Import.call(path.read, actor: Audit::SYSTEM)
    expect(first).to have_attributes(ok?: true, created: file.rules.map { |rule| rule.definition.key })
    expect(CisRule.enabled.count).to eq(file.rules.size)
    expect(CisRules::Import.call(path.read, actor: Audit::SYSTEM)).to have_attributes(ok?: true, changed?: false)
  end

  it "has fixtures for exactly its rules, and every fixture value is one the manifest accepts for the fact" do
    expect(fixtures.keys).to match_array(file.rules.map { |rule| rule.definition.key })
    file.rules.map(&:definition).each do |rule|
      fact = ConfigManifest.current.fact(rule.fact)
      values = fixtures.fetch(rule.key, {}).values_at("pass", "fail") + fixtures.fetch(rule.key, {}).values_at("also_pass", "also_fail").compact.flatten(1)
      values.each { |value| expect(fact.value_errors(value)).to eq([]), "#{rule.key}: #{value.inspect} #{fact.value_errors(value).join(', ')}" }
    end
  end

  file.rules.map(&:definition).each do |rule|
    cases = fixtures.fetch(rule.key, {})
    it "#{rule.key} passes and fails on its fixtures" do
      expect(cases.keys).to include("pass", "fail")
      { "pass" => [ cases["pass"], *cases["also_pass"] ], "fail" => [ cases["fail"], *cases["also_fail"] ] }.each do |expected, values|
        values.each do |value|
          outcome = CisRules::Evaluator.call(rule, facts(rule, value), debian13)
          expect(outcome.result).to eq(expected), "#{rule.key} with #{value.inspect}: #{outcome.result} (#{outcome.reason})"
        end
      end
    end
  end

  it "applies to Debian 13 only, and is not_readable when a fact cannot be read" do
    rule = file.rules.first.definition
    expect(CisRules::Evaluator.call(rule, facts(rule, fixtures.dig(rule.key, "pass")), { "id" => "debian", "version_id" => "12" }).result).to eq("not_applicable")
    unreadable = { rule.fact => { "state" => "unreadable", "value" => nil, "reason" => "Permission denied." } }
    expect(CisRules::Evaluator.call(rule, unreadable, debian13)).to have_attributes(result: "not_readable", reason: "Permission denied.")
  end

  describe "wording (DEC-10)" do
    definitions = file.rules.map(&:definition)

    it "references a CIS Debian Linux 13 v1.0.0 section number only, as a pointer" do
      expect(definitions.map(&:reference)).to all(match(/\ACIS Debian Linux 13 v1\.0\.0 \d+(\.\d+)*\z/))
    end

    it "gives every rule its own title, in short sentences of our own, never claiming compliance" do
      titles = definitions.map(&:title)
      expect(titles.uniq.size).to eq(titles.size)
      expect(titles).to all(satisfy { |title| title.length.between?(10, 80) && !title.start_with?("Ensure") })
      texts = definitions.flat_map { |rule| [ rule.title, rule.remediation ] }
      expect(texts.grep(/complian/i)).to eq([])
    end
  end
end

# The product says "CIS-aligned", never "CIS compliant" (DEC-10): any line in the docs, the dashboard, or the rule
# files that names CIS compliance must be saying that it is not. A "compliance view" is a page, not a claim.
RSpec.describe "CIS wording across the repository (DEC-10)" do
  CLAIM = /\bCIS[- ]complian(t|ce)\b|\bcomplian(t|ce) (with|to) (the )?CIS\b/i
  root = Rails.root.join("..")
  globs = %w[docs/**/*.md docs/**/*.html cmdb/app/**/*.{rb,erb} cmdb/config/rules/**/*.yml cmdb/README.md README.md]

  it "never claims CIS compliance" do
    offenders = globs.flat_map { |glob| Dir.glob(root.join(glob).to_s) }.uniq.flat_map do |name|
      File.readlines(name).each_with_index.filter_map do |line, index|
        next unless line.match?(CLAIM)
        next if line.match?(/\b(never|not)\b/i)

        "#{Pathname(name).relative_path_from(root)}:#{index + 1}: #{line.strip}"
      end
    end
    expect(offenders).to eq([])
  end

  it "recognises a claim, and a denial of one" do
    expect([ "The fleet is CIS compliant.", "CIS-compliance report", "compliant with the CIS benchmark" ]).to all(match(CLAIM))
    expect([ "A fleet compliance view lists every host with its CIS pass rate.", "CIS-aligned checks" ].grep(CLAIM)).to eq([])
  end
end
