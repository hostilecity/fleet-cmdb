require "rails_helper"

# Checking a config report against the fact manifest (P2-S02, FR-2.1, DEC-08).
RSpec.describe AgentApi::ConfigReport do
  let(:example) { ApiContract.example("config.request", "typical") }

  def fact(key, type, since: 1, **constraints)
    ConfigManifest::Fact.new(key:, type:, since:, description: "A fact.", constraints: ConfigManifest::CONSTRAINTS.fetch(type).merge(constraints.transform_keys(&:to_s)), example: nil)
  end

  # Version 2 added sshd.banner, so a report against version 1 leaves it out.
  let(:manifest) do
    ConfigManifest::Manifest.new(version: 2, facts: [
      fact("sshd.permitrootlogin", "string", max_length: 32), fact("sshd.maxauthtries", "integer", minimum: 0, maximum: 1000),
      fact("users.login", "string_list"), fact("sshd.ciphers", "string_list", ordered: true), fact("file:/etc/shadow", "file_attributes"),
      fact("service:ssh.service", "service_state"), fact("sshd.banner", "string", since: 2)
    ])
  end

  def report(facts, manifest_version: 1) = described_class.new(example.merge("manifest_version" => manifest_version, "facts" => facts), manifest:)

  def ok(value) = { "state" => "ok", "value" => value, "reason" => nil }

  def problems(facts, **options)
    report(facts, **options)
    raise "expected a validation failure"
  rescue AgentApi::ValidationFailed => e
    e.details
  end

  it "records every manifest fact, missing ones with a reason that says why, in key order" do
    facts = report({ "sshd.permitrootlogin" => ok("no"), "file:/etc/shadow" => { "state" => "unreadable", "value" => nil, "reason" => "Permission\u0007 denied" } }).facts
    expect(facts.keys).to eq(manifest.facts.map(&:key))
    expect(facts.keys).to eq(facts.keys.sort)
    expect(facts["sshd.permitrootlogin"]).to eq(ok("no"))
    expect(facts["file:/etc/shadow"]).to eq("state" => "unreadable", "value" => nil, "reason" => "Permission denied")
    expect(facts["sshd.maxauthtries"]).to eq("state" => "missing", "value" => nil, "reason" => "The agent's report did not include this fact.")
    expect(facts["sshd.banner"]).to eq("state" => "missing", "value" => nil, "reason" => "Added in manifest version 2; the agent reported against version 1.")
  end

  it "counts the facts in each state" do
    counts = report({ "sshd.permitrootlogin" => ok("no"), "sshd.banner" => { "state" => "unsupported", "value" => nil, "reason" => "no sshd" } }).counts
    expect(counts).to eq("ok" => 1, "unreadable" => 0, "unsupported" => 1, "missing" => 5)
  end

  it "sorts a list whose order does not matter, keeps one whose order does, and hashes the same facts the same in any order" do
    first = report({ "users.login" => ok(%w[root admin]), "sshd.ciphers" => ok(%w[b a]), "sshd.permitrootlogin" => ok("no") })
    second = report({ "sshd.permitrootlogin" => ok("no"), "sshd.ciphers" => ok(%w[b a]), "users.login" => ok(%w[admin root]) })
    expect(first.facts["users.login"]["value"]).to eq(%w[admin root])
    expect(first.facts["sshd.ciphers"]["value"]).to eq(%w[b a])
    expect(first.content_hash).to eq(second.content_hash)
    expect(report({ "sshd.ciphers" => ok(%w[a b]) }).content_hash).not_to eq(report({ "sshd.ciphers" => ok(%w[b a]) }).content_hash)
  end

  it "hashes a change of state or reason as a change" do
    hashes = [ ok(nil), { "state" => "unreadable", "value" => nil, "reason" => "denied" }, { "state" => "unreadable", "value" => nil, "reason" => "busy" } ]
             .map { |entry| report({ "file:/etc/shadow" => entry }).content_hash }
    expect(hashes.uniq.size).to eq(3)
  end

  it "keeps only a file's or unit's declared fields, in a fixed order (DEC-08)" do
    facts = report({ "file:/etc/shadow" => ok({ "group" => "shadow", "owner" => "root", "mode" => "0640", "acl" => "x" }),
                     "service:ssh.service" => ok({ "enabled" => "enabled", "active" => "active", "sub" => "running" }) }).facts
    expect(facts["file:/etc/shadow"]["value"].to_a).to eq([ %w[mode 0640], %w[owner root], %w[group shadow] ])
    expect(facts["service:ssh.service"]["value"].to_a).to eq([ %w[active active], %w[enabled enabled] ])
  end

  it "lists the fields it drops from a file or unit as JSON Pointers, for the log (review of #108)" do
    parsed = report({ "file:/etc/shadow" => ok({ "mode" => "0640", "owner" => "root", "group" => "shadow", "acl" => "x", "a/b" => 1 }),
                      "service:ssh.service" => ok({ "active" => "active", "enabled" => "enabled" }) })
    expect(parsed.ignored_fields).to eq([ "/facts/file:~1etc~1shadow/value/acl", "/facts/file:~1etc~1shadow/value/a~1b" ])
  end

  it "stores a missing file or unit as ok with a null value, not as missing" do
    expect(report({ "file:/etc/shadow" => ok(nil) }).facts["file:/etc/shadow"]).to eq(ok(nil))
  end

  it "ignores keys the manifest does not have, and lists them" do
    parsed = report({ "sshd.someday" => ok("yes"), "file:/etc/other" => ok(nil), "sshd.permitrootlogin" => ok("no") })
    expect(parsed.ignored_keys).to eq([ "file:/etc/other", "sshd.someday" ])
    expect(parsed.facts).not_to have_key("sshd.someday")
  end

  it "refuses values of the wrong type or past the manifest's limits, naming each fact" do
    details = problems({ "sshd.permitrootlogin" => ok("x" * 33), "sshd.maxauthtries" => ok("4"), "users.login" => ok([ "root", 1 ]),
                         "file:/etc/shadow" => ok({ "mode" => "0640", "owner" => "", "group" => "shadow" }), "service:ssh.service" => ok(true) })
    expect(details).to contain_exactly(
      { "pointer" => "/facts/sshd.permitrootlogin/value", "problem" => "is longer than 32 characters (sshd.permitrootlogin is string)" },
      { "pointer" => "/facts/sshd.maxauthtries/value", "problem" => "must be an integer (sshd.maxauthtries is integer)" },
      { "pointer" => "/facts/users.login/value", "problem" => "must be a list of strings (users.login is string_list)" },
      { "pointer" => "/facts/file:~1etc~1shadow/value", "problem" => "owner must be a string of 1 to 64 characters (file:/etc/shadow is file_attributes)" },
      a_hash_including("pointer" => "/facts/service:ssh.service/value")
    )
  end

  it "refuses an integer outside the manifest's range, and a float" do
    expect(problems({ "sshd.maxauthtries" => ok(1001) }).first["problem"]).to start_with("must be from 0 to 1000")
    expect(problems({ "sshd.maxauthtries" => ok(4.0) }).first["problem"]).to start_with("must be an integer")
  end

  it "refuses a NUL in a value, which PostgreSQL cannot store" do
    expect(problems({ "sshd.permitrootlogin" => ok("n\u0000o") })).to eq([ { "pointer" => "/facts/sshd.permitrootlogin/value", "problem" => "contains a NUL character (sshd.permitrootlogin is string)" } ])
    expect(problems({ "users.login" => ok([ "ro\u0000ot" ]) }).first["pointer"]).to eq("/facts/users.login/value")
  end

  it "refuses a manifest version newer than the server's, and takes an older or equal one" do
    expect(problems({}, manifest_version: 3)).to eq([ { "pointer" => "/manifest_version", "problem" => "is newer than this server's fact manifest (version 2); fetch GET /api/v1/manifest/config again" } ])
    expect(report({}, manifest_version: 2).facts["sshd.banner"]["reason"]).to eq("The agent's report did not include this fact.")
  end

  it "gives a reason left empty by removing control characters a readable one" do
    entry = report({ "file:/etc/shadow" => { "state" => "unreadable", "value" => nil, "reason" => "\u0001\u0002" } }).facts["file:/etc/shadow"]
    expect(entry["reason"]).to eq("The agent gave no readable reason.")
  end

  it "accepts every valid docs/api example against the real manifest" do
    ApiContract.examples_for("config.request", kind: "valid").each do |e|
      expect { described_class.new(e.data) }.not_to raise_error, e.name
    end
  end

  it "fits a report at every limit of the real manifest within the endpoint's limit" do
    facts = ConfigManifest.current.facts.to_h do |f|
      c = f.constraints
      value = case f.type
      when "string" then "a" * c["max_length"]
      when "integer" then c["maximum"]
      when "boolean" then true
      when "string_list" then Array.new(c["max_items"]) { |i| i.to_s.rjust(c["item_max_length"], "a") }
      when "file_attributes" then { "mode" => "0644", "owner" => "a" * 64, "group" => "a" * 64 }
      when "service_state" then { "active" => "a" * 32, "enabled" => "a" * 32 }
      end
      [ f.key, ok(value) ]
    end
    body = example.merge("facts" => facts).to_json
    expect(body.bytesize).to be < Api::V1::ConfigReportsController.max_body_bytes
    expect { described_class.new(JSON.parse(body)) }.not_to raise_error
  end
end
