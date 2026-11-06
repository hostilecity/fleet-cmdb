require "rails_helper"

# Which operators fit which fact types (P2-S04, DEC-12). The JSON Schema checks shapes; these are the checks
# against the manifest.
RSpec.describe CisRules::Condition do
  def problems(fact, condition) = described_class.errors(condition, ConfigManifest.current.fact(fact), "/c")

  it "accepts each operator on the fact types it works on" do
    {
      "sshd.loglevel" => [ { "eq" => "INFO" }, { "ne" => "QUIET" }, { "in" => [ "INFO" ] }, { "not_in" => [ "QUIET" ] }, { "matches" => "INFO|VERBOSE" }, { "present" => true }, { "absent" => true } ],
      "sshd.maxauthtries" => [ { "eq" => 4 }, { "in" => [ 3, 4 ] }, { "gte" => 1 }, { "lte" => 4 } ],
      "sshd.x11forwarding" => [ { "eq" => false }, { "ne" => true }, { "in" => [ false ] } ],
      "sshd.ciphers" => [ { "eq" => [ "aes256-gcm@openssh.com" ] }, { "in" => [ "a" ] }, { "not_in" => [ "3des-cbc" ] }, { "matches" => "aes.*" } ],
      "file:/etc/shadow" => [ { "mode_at_most" => "0640" }, { "field" => "mode", "mode_at_most" => "0640" }, { "field" => "owner", "eq" => "root" },
                              { "field" => "group", "in" => [ "shadow" ] }, { "field" => "mode", "matches" => "0[0-6]40" }, { "absent" => true } ],
      "service:ssh.service" => [ { "field" => "active", "eq" => "active" }, { "field" => "enabled", "not_in" => [ "masked" ] }, { "present" => true } ]
    }.each do |fact, conditions|
      conditions.each { |condition| expect(problems(fact, condition)).to eq([]), "#{fact} #{condition}" }
    end
  end

  it "refuses an operator on a fact type it cannot test, naming why" do
    {
      [ "sshd.loglevel", { "gte" => 1 } ] => "gte works only on an integer fact, and sshd.loglevel is string",
      [ "sshd.maxauthtries", { "eq" => "4" } ] => "eq needs an integer",
      [ "sshd.maxauthtries", { "in" => [ 4, "5" ] } ] => "in needs a list of integers",
      [ "sshd.x11forwarding", { "eq" => "no" } ] => "eq needs a boolean",
      [ "sshd.ciphers", { "eq" => "aes" } ] => "eq needs a list of strings",
      [ "sshd.ciphers", { "in" => [ 1 ] } ] => "in needs a list of strings",
      [ "sshd.loglevel", { "mode_at_most" => "0640" } ] => "mode_at_most works only on a file fact, or its mode field",
      [ "file:/etc/shadow", { "field" => "owner", "mode_at_most" => "0640" } ] => "mode_at_most works only on a file fact, or its mode field",
      [ "file:/etc/shadow", { "eq" => "root" } ] => "eq needs a field for a file_attributes fact (mode, owner, group)",
      [ "file:/etc/shadow", { "field" => "active", "eq" => "x" } ] => "field active is not part of a file_attributes value",
      [ "sshd.loglevel", { "field" => "mode", "eq" => "x" } ] => "field mode is not part of a string value",
      [ "service:ssh.service", { "matches" => "x" } ] => "matches needs a field for a service_state fact (active, enabled)",
      [ "sshd.x11forwarding", { "matches" => "x" } ] => "matches works only on a string or list fact, and sshd.x11forwarding is boolean",
      [ "sshd.loglevel", { "matches" => "(a" } ] => "matches is not a valid regular expression"
    }.each do |(fact, condition), problem|
      expect(problems(fact, condition).join).to start_with("/c: #{problem}"), "#{fact} #{condition}"
    end
  end

  it "checks every branch of a combinator, with a pointer to each" do
    condition = { "all" => [ { "eq" => "INFO" }, { "any" => [ { "gte" => 1 }, { "not" => { "lte" => 2 } } ] } ] }
    expect(problems("sshd.loglevel", condition)).to eq([ "/c/all/1/any/0: gte works only on an integer fact, and sshd.loglevel is string",
                                                         "/c/all/1/any/1/not: lte works only on an integer fact, and sshd.loglevel is string" ])
  end

  it "limits nesting and size" do
    deep = (1..9).reduce({ "eq" => "INFO" }) { |inner, _| { "not" => inner } }
    expect(problems("sshd.loglevel", deep)).to eq([ "/c#{'/not' * 8}: is nested more than 8 deep" ])
    wide = { "all" => Array.new(16) { { "all" => Array.new(4) { { "eq" => "INFO" } } } } }
    expect(problems("sshd.loglevel", wide)).to eq([ "/c: has more than 64 conditions" ])
  end

  it "anchors patterns at both ends and refuses one that would escape the anchors" do
    regexp = described_class.regexp("INFO|VERBOSE")
    expect([ regexp.match?("INFO"), regexp.match?("VERBOSE"), regexp.match?("xINFO"), regexp.match?("VERBOSEx") ]).to eq([ true, true, false, false ])
    expect(regexp.timeout).to eq(described_class::REGEXP_TIMEOUT)
    expect { described_class.regexp("a)|(b") }.to raise_error(RegexpError)
  end
end
