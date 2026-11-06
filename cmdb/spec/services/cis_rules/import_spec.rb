require "rails_helper"

# Importing rule files (P2-S04, FR-2.2, FR-S.3).
RSpec.describe CisRules::Import do
  def rule(**overrides)
    { "key" => "ssh-root-login-off", "reference" => "CIS Debian 13 5.1.20", "title" => "SSH does not let root log in", "severity" => "high",
      "applies_to" => [ { "distribution" => "debian", "versions" => [ "13" ] } ], "fact" => "sshd.permitrootlogin",
      "condition" => { "eq" => "no" }, "remediation" => "Set PermitRootLogin to no." }.merge(overrides.transform_keys(&:to_s))
  end

  def file(*rules) = { "format_version" => 1, "rules" => rules }.to_yaml

  def import(*rules, disable_missing: false) = described_class.call(file(*rules), actor: Audit::SYSTEM, disable_missing:)

  def entries(action) = AuditEntry.where(action:).order(:id)

  let(:second) { rule(key: "ssh-max-auth-tries", fact: "sshd.maxauthtries", condition: { "lte" => 4 }, severity: "medium") }

  it "creates each rule at version 1, enabled, and audits it with its values" do
    result = import(rule, second)
    expect(result).to have_attributes(ok?: true, changed?: true, created: [ "ssh-root-login-off", "ssh-max-auth-tries" ], versioned: [], unchanged: [])
    stored = CisRule.find_by!(key: "ssh-root-login-off")
    expect(stored).to have_attributes(enabled: true)
    expect(stored.current_version).to have_attributes(version: 1, fact: "sshd.permitrootlogin", condition: { "eq" => "no" }, severity: "high")
    expect(stored.current_version.definition).to eq(CisRules::Definition.from_h(rule))
    entry = entries(Audit::Actions::RULE_CREATED).first
    expect(entry).to have_attributes(actor_type: "system", target_type: "CisRule", target_id: stored.id)
    expect(entry.changeset).to include("version" => [ nil, 1 ], "enabled" => [ nil, true ], "condition" => [ nil, { "eq" => "no" } ], "title" => [ nil, rule["title"] ])
  end

  it "imports nothing from an invalid file and reports every error (P2-S04)" do
    result = import(rule, rule(key: "b", fact: "nope.fact"), rule(key: "c", severity: "urgent"))
    expect(result).to have_attributes(ok?: false, changed?: false, created: [])
    expect(result.errors.size).to eq(2)
    expect([ CisRule.count, CisRuleVersion.count, AuditEntry.count ]).to eq([ 0, 0, 0 ])
  end

  it "creates no version and no audit entry when the same file is imported again, whatever its key order (P2-S04)" do
    import(rule, second)
    expect { @result = described_class.call(file(second, rule.to_a.reverse.to_h), actor: Audit::SYSTEM) }.not_to change { [ CisRuleVersion.count, AuditEntry.count ] }
    expect(@result).to have_attributes(unchanged: [ "ssh-max-auth-tries", "ssh-root-login-off" ], changed?: false)
  end

  it "makes an edit a new version, audits the before and after values, and keeps the old version readable (P2-S04)" do
    import(rule)
    result = import(rule(condition: { "in" => [ "no", "prohibit-password" ] }, title: "Root cannot log in with a password"))
    expect(result.versioned).to eq([ "ssh-root-login-off" ])

    stored = CisRule.find_by!(key: "ssh-root-login-off")
    expect(stored.versions.map { |v| [ v.version, v.condition ] }).to eq([ [ 1, { "eq" => "no" } ], [ 2, { "in" => [ "no", "prohibit-password" ] } ] ])
    expect(stored.current_version.version).to eq(2)
    expect(stored.versions.first.definition).to eq(CisRules::Definition.from_h(rule))
    expect(entries(Audit::Actions::RULE_EDITED).sole.changeset).to eq(
      "condition" => [ { "eq" => "no" }, { "in" => [ "no", "prohibit-password" ] } ],
      "title" => [ "SSH does not let root log in", "Root cannot log in with a password" ], "version" => [ 1, 2 ]
    )
  end

  it "never changes or deletes a stored version, current or not (review of #101)" do
    import(rule)
    import(rule(title: "second"))
    old, current = CisRule.sole.versions.to_a
    [ old, current ].each do |version|
      expect { version.update!(title: "rewritten") }.to raise_error(ActiveRecord::ReadOnlyRecord)
      expect { version.destroy! }.to raise_error(ActiveRecord::ReadOnlyRecord)
      expect { version.delete }.to raise_error(ActiveRecord::ReadOnlyRecord)
    end
    expect(CisRuleVersion.count).to eq(2)
  end

  describe "enabling and disabling (FR-S.3)" do
    it "creates a rule disabled when the file says so, with no separate toggle" do
      result = import(rule(enabled: false))
      expect(result).to have_attributes(created: [ "ssh-root-login-off" ], disabled: [])
      expect(CisRule.sole.enabled).to be(false)
      expect(entries(Audit::Actions::RULE_CREATED).sole.changeset["enabled"]).to eq([ nil, false ])
    end

    it "changes the flag only when the file states it, and audits each toggle" do
      import(rule)
      expect(import(rule(enabled: false))).to have_attributes(disabled: [ "ssh-root-login-off" ], unchanged: [ "ssh-root-login-off" ])
      expect(import(rule).disabled + import(rule).enabled).to eq([]) # a file that does not say leaves the flag alone
      expect(CisRule.sole.enabled).to be(false)
      expect(import(rule(enabled: true)).enabled).to eq([ "ssh-root-login-off" ])
      expect(entries(Audit::Actions::RULE_DISABLED).sole.changeset).to eq("enabled" => [ true, false ])
      expect(entries(Audit::Actions::RULE_ENABLED).sole.changeset).to eq("enabled" => [ false, true ])
      expect(CisRuleVersion.count).to eq(1)
    end

    it "leaves rules the file does not list unchanged, unless asked to disable them" do
      import(rule, second)
      expect(import(rule).disabled).to eq([])
      expect(CisRule.enabled.count).to eq(2)
      expect(import(rule, disable_missing: true).disabled).to eq([ "ssh-max-auth-tries" ])
      expect(CisRule.find_by!(key: "ssh-max-auth-tries")).to have_attributes(enabled: false)
      expect(import(rule, disable_missing: true).disabled).to eq([]) # already disabled
    end

    it "enable! and disable! report whether the flag changed" do
      import(rule)
      stored = CisRule.sole
      CisRule.transaction do
        expect([ stored.enable!(actor: Audit::SYSTEM), stored.disable!(actor: Audit::SYSTEM), stored.disable!(actor: Audit::SYSTEM) ]).to eq([ false, true, false ])
      end
    end
  end

  it "rolls back everything when a write fails part way" do
    import(rule)
    allow(Audit).to receive(:record).and_call_original
    allow(Audit).to receive(:record).with(hash_including(action: Audit::Actions::RULE_EDITED)).and_raise(ActiveRecord::StatementInvalid, "boom")
    expect { import(second, rule(title: "changed")) }.to raise_error(ActiveRecord::StatementInvalid)
    expect([ CisRule.count, CisRuleVersion.count ]).to eq([ 1, 1 ])
  end

  it "refuses a rule key that does not fit the format, even outside a file" do
    expect { CisRule.create!(key: "Not A Key") }.to raise_error(ActiveRecord::RecordInvalid)
  end
end
