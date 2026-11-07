require "rails_helper"
require "ripper"

# The rule evaluator (P2-S05, FR-2.2, DEC-12, AC-2.5, AC-2.6).
RSpec.describe CisRules::Evaluator do
  DEBIAN13 = { "id" => "debian", "version_id" => "13" }.freeze

  def rule(fact, condition, applies_to: [ { "distribution" => "debian", "versions" => [ "13" ] } ])
    CisRules::Definition.new(key: "r", reference: "x", title: "t", severity: "low", applies_to:, fact:, condition:, remediation: "r")
  end

  def ok(value) = { "state" => "ok", "value" => value, "reason" => nil }

  def evaluate(fact, condition, value, os: DEBIAN13, **options) = described_class.call(rule(fact, condition, **options), { fact => ok(value) }, os)

  def result(...) = evaluate(...).result

  # Every operator, for a value that passes and one that fails (AC-2.6). Each is also checked for not applicable
  # and not readable below.
  CASES = {
    "eq string" => [ "sshd.permitrootlogin", { "eq" => "no" }, "no", "yes" ],
    "eq integer" => [ "sshd.maxauthtries", { "eq" => 4 }, 4, 5 ],
    "eq boolean" => [ "sshd.x11forwarding", { "eq" => false }, false, true ],
    "eq unordered list, in any order" => [ "services.running", { "eq" => [ "ssh.service", "cron.service" ] }, [ "cron.service", "ssh.service" ], [ "ssh.service" ] ],
    "eq ordered list, only in its order" => [ "sshd.ciphers", { "eq" => [ "b", "a" ] }, [ "b", "a" ], [ "a", "b" ] ],
    "ne" => [ "sshd.allowtcpforwarding", { "ne" => "yes" }, "no", "yes" ],
    "ne on a missing unit" => [ "service:cups.service", { "field" => "active", "ne" => "active" }, nil, { "active" => "active", "enabled" => "enabled" } ],
    "in" => [ "sshd.loglevel", { "in" => [ "INFO", "VERBOSE" ] }, "VERBOSE", "QUIET" ],
    "in on a list: every entry" => [ "sshd.ciphers", { "in" => [ "a", "b" ] }, [ "b" ], [ "b", "c" ] ],
    "not_in" => [ "sshd.loglevel", { "not_in" => [ "QUIET" ] }, "INFO", "QUIET" ],
    "not_in on a list: no entry" => [ "services.running", { "not_in" => [ "telnet.socket" ] }, [ "ssh.service" ], [ "ssh.service", "telnet.socket" ] ],
    "not_in on an absent value" => [ "file:/etc/shadow", { "field" => "owner", "not_in" => [ "nobody" ] }, nil, { "mode" => "0640", "owner" => "nobody", "group" => "shadow" } ],
    "present" => [ "file:/etc/issue.net", { "present" => true }, { "mode" => "0644", "owner" => "root", "group" => "root" }, nil ],
    "absent" => [ "service:telnet.socket", { "absent" => true }, nil, { "active" => "inactive", "enabled" => "disabled" } ],
    "gte" => [ "login_defs.pass_min_days", { "gte" => 1 }, 1, 0 ],
    "lte" => [ "sshd.maxauthtries", { "lte" => 4 }, 4, 6 ],
    "matches, anchored" => [ "sshd.loglevel", { "matches" => "INFO|VERBOSE" }, "INFO", "INFOx" ],
    "matches on a list: every entry" => [ "sshd.macs", { "matches" => "hmac-sha2-.*" }, [ "hmac-sha2-256", "hmac-sha2-512" ], [ "hmac-sha2-256", "hmac-md5" ] ],
    "mode_at_most" => [ "file:/etc/shadow", { "mode_at_most" => "0640" }, { "mode" => "0600", "owner" => "root", "group" => "shadow" }, { "mode" => "0644", "owner" => "root", "group" => "shadow" } ],
    "mode_at_most counts special bits" => [ "file:/etc/crontab", { "field" => "mode", "mode_at_most" => "0755" }, { "mode" => "755", "owner" => "root", "group" => "root" }, { "mode" => "4755", "owner" => "root", "group" => "root" } ],
    "field" => [ "service:ssh.service", { "field" => "enabled", "eq" => "enabled" }, { "active" => "active", "enabled" => "enabled" }, { "active" => "active", "enabled" => "disabled" } ],
    "all" => [ "sshd.maxauthtries", { "all" => [ { "gte" => 1 }, { "lte" => 4 } ] }, 3, 0 ],
    "any" => [ "sshd.loglevel", { "any" => [ { "eq" => "INFO" }, { "eq" => "VERBOSE" } ] }, "INFO", "DEBUG" ],
    "not" => [ "sshd.permitrootlogin", { "not" => { "eq" => "yes" } }, "no", "yes" ]
  }.freeze

  CASES.each do |name, (fact, condition, passing, failing)|
    describe name do
      it "passes and fails, observing the value" do
        expect(evaluate(fact, condition, passing)).to eq(described_class::Outcome.new(result: "pass", observed: passing, reason: nil))
        expect(evaluate(fact, condition, failing)).to eq(described_class::Outcome.new(result: "fail", observed: failing, reason: nil))
      end

      it "is not applicable on another distribution or release" do
        expect(result(fact, condition, passing, os: { "id" => "ubuntu", "version_id" => "24.04" })).to eq("not_applicable")
        expect(result(fact, condition, passing, os: { "id" => "debian", "version_id" => "12" })).to eq("not_applicable")
      end

      it "is not readable, with the agent's reason, when the fact is unreadable" do
        facts = { fact => { "state" => "unreadable", "value" => nil, "reason" => "permission denied reading the file" } }
        expect(described_class.call(rule(fact, condition), facts, DEBIAN13))
          .to eq(described_class::Outcome.new(result: "not_readable", observed: nil, reason: "permission denied reading the file"))
      end
    end
  end

  describe "absent values (null: no such file or unit)" do
    it "equals nothing, is in nothing, matches nothing, and has no parts" do
      expect([ result("file:/etc/shadow", { "field" => "owner", "eq" => "root" }, nil), result("file:/etc/shadow", { "field" => "group", "in" => [ "shadow" ] }, nil),
               result("file:/etc/shadow", { "field" => "mode", "matches" => ".*" }, nil), result("file:/etc/shadow", { "mode_at_most" => "0777" }, nil),
               result("service:ssh.service", { "present" => true }, nil) ]).to all(eq("fail"))
    end

    it "is never a plain value: the manifest has no null for those, so a null one is not readable" do
      expect(evaluate("sshd.banner", { "eq" => "none" }, nil)).to have_attributes(result: "not_readable", reason: include("must be a string"))
    end

    it "passes in, not_in, and matches when a list is empty, since every (and no) entry fits" do
      expect([ result("sshd.ciphers", { "in" => [ "a" ] }, []), result("sshd.ciphers", { "not_in" => [ "a" ] }, []), result("sshd.ciphers", { "matches" => "a" }, []) ]).to all(eq("pass"))
    end
  end

  describe "applicability" do
    it "matches a distribution on any release when no versions are given, and names what it applies to otherwise" do
      any_release = [ { "distribution" => "debian" } ]
      expect(result("sshd.permitrootlogin", { "eq" => "no" }, "no", os: { "id" => "debian", "version_id" => nil }, applies_to: any_release)).to eq("pass")
      expect(evaluate("sshd.permitrootlogin", { "eq" => "no" }, "no", os: { "id" => "debian", "version_id" => nil }))
        .to have_attributes(result: "not_applicable", reason: "Applies to debian 13; this host runs debian.")
      two = [ { "distribution" => "debian", "versions" => [ "12", "13" ] }, { "distribution" => "ubuntu" } ]
      expect(evaluate("sshd.permitrootlogin", { "eq" => "no" }, "no", os: { "id" => "fedora", "version_id" => "41" }, applies_to: two).reason)
        .to eq("Applies to debian 12/13, ubuntu; this host runs fedora 41.")
    end

    it "is not readable, before anything else, when the host has not reported its operating system" do
      [ nil, {}, { "id" => nil }, { "id" => "", "version_id" => "13" }, { "id" => "  " } ].each do |os|
        expect(described_class.call(rule("sshd.permitrootlogin", { "eq" => "no" }), {}, os))
          .to have_attributes(result: "not_readable", reason: "The host has not reported its operating system.")
      end
    end

    it "is not applicable before it looks at the fact" do
      expect(described_class.call(rule("sshd.permitrootlogin", { "eq" => "no" }), {}, { "id" => "ubuntu" }).result).to eq("not_applicable")
    end
  end

  describe "not readable (AC-2.5)" do
    def outcome(facts) = described_class.call(rule("sshd.permitrootlogin", { "eq" => "no" }), facts, DEBIAN13)

    it "carries the agent's reason for an unsupported fact, or says what the agent reported" do
      expect(outcome("sshd.permitrootlogin" => { "state" => "unsupported", "value" => nil, "reason" => "sshd is not installed" }).reason).to eq("sshd is not installed")
      expect(outcome("sshd.permitrootlogin" => { "state" => "unreadable", "value" => nil, "reason" => "" }).reason).to eq("The agent reported this fact as unreadable.")
    end

    it "covers a fact the report does not include" do
      [ {}, { "sshd.permitrootlogin" => { "state" => "missing", "value" => nil, "reason" => nil } } ].each do |facts|
        expect(outcome(facts)).to have_attributes(result: "not_readable", reason: "The host's report does not include this fact.")
      end
    end

    it "carries the reason a config report recorded for a missing fact (P2-S02)" do
      reason = "Added in manifest version 2; the agent reported against version 1."
      expect(outcome("sshd.permitrootlogin" => { "state" => "missing", "value" => nil, "reason" => reason })).to have_attributes(result: "not_readable", reason:)
    end

    it "covers a value that does not fit the manifest, such as an oversize one, rather than evaluating it" do
      expect(outcome("sshd.permitrootlogin" => ok("x" * 10_000)))
        .to have_attributes(result: "not_readable", reason: "The reported value does not fit the fact manifest: it is longer than 32 characters.")
      expect(outcome("sshd.permitrootlogin" => ok(true)).reason).to include("must be a string")
    end

    it "truncates a long reason" do
      expect(outcome("sshd.permitrootlogin" => { "state" => "unreadable", "value" => nil, "reason" => "x" * 2_000 }).reason.length).to eq(512)
    end
  end

  describe "time bounds (P2-S05)" do
    it "gives up on a catastrophic-backtracking pattern within its time limit and reports not readable" do
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      outcome = evaluate("sshd.banner", { "matches" => "(\\w+\\s?)+\\1$" }, "#{'a' * 30}!")
      expect(outcome).to have_attributes(result: "not_readable", reason: "Matching the value took longer than allowed, so it was not evaluated.")
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 1
    end

    it "stops matching a long list when the rule's time budget runs out" do
      stub_const("#{described_class}::TIME_BUDGET", -1)
      expect(result("services.running", { "matches" => ".*" }, Array.new(1_000) { |i| "unit-#{i}.service" })).to eq("not_readable")
    end

    it "is not readable when the last match ends after the budget, even if it started in time (review of #102)" do
      clock = [ 0.0, 0.1, 0.3 ].each # when the budget starts, the check before the match, and the one after it
      allow(Process).to receive(:clock_gettime).with(Process::CLOCK_MONOTONIC) { clock.next }
      expect(result("sshd.loglevel", { "matches" => "INFO" }, "INFO")).to eq("not_readable")
    end

    it "evaluates a large list well within the budget" do
      units = Array.new(1_000) { |i| format("unit-%04d.service", i) }
      expect(result("services.running", { "all" => [ { "matches" => "[a-z0-9-]+\\.service" }, { "not_in" => [ "telnet.socket" ] } ] }, units)).to eq("pass")
    end
  end

  describe "observed values" do
    it "keeps a value as reported, and cuts a long one short at a character boundary, saying so" do
      units = Array.new(200) { |i| format("ünit-%04d.service", i) }
      observed = evaluate("services.running", { "present" => true }, units).observed
      expect(observed).to be_a(String).and(end_with("… (truncated from #{units.to_json.bytesize} bytes)"))
      expect(observed.to_json.bytesize).to be <= described_class::OBSERVED_MAX_BYTES
      plain = evaluate("services.running", { "present" => true }, Array.new(200) { |i| format("unit-%04d.service", i) }).observed
      expect(plain.to_json.bytesize).to be_between(described_class::OBSERVED_MAX_BYTES - 64, described_class::OBSERVED_MAX_BYTES) # review of #102
      quotes = evaluate("sshd.ciphers", { "present" => true }, Array.new(64) { "\\\"" * 20 }).observed
      expect(quotes.to_json.bytesize).to be <= described_class::OBSERVED_MAX_BYTES
      expect(observed).to be_valid_encoding
      expect(evaluate("sshd.ciphers", { "present" => true }, [ "b", "a" ]).observed).to eq([ "b", "a" ]) # as reported, not normalised
    end
  end

  it "returns only the four results" do
    outcomes = CASES.values.flat_map { |fact, condition, passing, _| [ evaluate(fact, condition, passing), evaluate(fact, condition, passing, os: nil) ] }
    expect(outcomes.map(&:result).uniq - described_class::RESULTS).to eq([])
  end

  it "raises, rather than passing, for an operator outside the closed list (the import refuses it first)" do
    expect { evaluate("sshd.loglevel", { "eval" => "INFO" }, "INFO") }.to raise_error(ArgumentError, 'unknown operator nil')
  end

  it "evaluates stored versions as well as definitions" do
    CisRules::Import.call({ "format_version" => 1, "rules" => [ rule("sshd.permitrootlogin", { "eq" => "no" }).fields.merge("key" => "r") ] }.to_yaml, actor: Audit::SYSTEM)
    expect(described_class.call(CisRuleVersion.sole, { "sshd.permitrootlogin" => ok("no") }, DEBIAN13).result).to eq("pass")
  end

  # No code evaluation of any kind (DEC-12, P2-S05): rule data is only ever compared, never run or used to pick a
  # method. Checked on the code's tokens, so words in strings and comments do not count.
  it "has no eval, dynamic dispatch, or shell in the rule code" do
    files = [ "lib/cis_rules.rb", *Dir["lib/cis_rules/**/*.rb"], *Dir["app/services/cis_rules/**/*.rb"] ].map { |path| Rails.root.join(path) }
    forbidden = %w[eval instance_eval class_eval module_eval instance_exec class_exec send public_send __send__ method define_method
                   constantize safe_constantize const_get system exec spawn popen Open3 binding load require]
    hits = files.flat_map do |path|
      Ripper.lex(path.read).filter_map do |(line, _), type, token|
        "#{path.relative_path_from(Rails.root)}:#{line}: #{token}" if type == :on_backtick || (%i[on_ident on_const].include?(type) && forbidden.include?(token))
      end
    end
    expect(files.size).to be >= 5
    expect(hits).to eq([])
    expect(Ripper.lex("x = `ls`; y.send(:a); eval(z)").filter_map { |_, type, token| token if type == :on_backtick || forbidden.include?(token) }).to eq(%w[` send eval])
  end
end
