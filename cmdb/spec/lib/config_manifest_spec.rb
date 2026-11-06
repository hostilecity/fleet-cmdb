require "rails_helper"

# The configuration fact manifest (P2-S01, FR-2.1)
RSpec.describe ConfigManifest do
  let(:manifest) { described_class.current }

  def load_yaml(data, &edit)
    data = YAML.safe_load(data.to_yaml)
    edit&.call(data)
    path = Rails.root.join("tmp/config_manifest_spec.yml")
    File.write(path, data.to_yaml)
    described_class.load(path)
  ensure
    FileUtils.rm_f(path)
  end

  let(:base) { { "manifest_version" => 1, "facts" => [ { "key" => "sshd.loglevel", "type" => "string", "since" => 1, "description" => "Log level.", "example" => "INFO" } ] } }

  describe "the published manifest" do
    it "loads, and every fact has an example value that its own rules accept" do
      expect(manifest.facts.size).to be > 80
      bad = manifest.facts.reject { |fact| fact.value_errors(fact.example).empty? }.map(&:key)
      expect(bad).to eq([])
    end

    it "covers the areas FR-2.1 lists: SSH, password and login policy, firewall, automatic updates, sensitive files, services, and users" do
      prefixes = manifest.facts.map { |f| f.key[/\A[a-z_]+(?=[.:])/] }.uniq
      expect(prefixes).to include("sshd", "login_defs", "pwquality", "firewall", "auto_updates", "file", "service", "services", "users")
      expect(manifest.fact("file:/etc/shadow")).to have_attributes(type: "file_attributes")
      expect(manifest.fact("service:ssh.service")).to have_attributes(type: "service_state")
    end

    it "has a version equal to the highest since, so no version is bumped for nothing" do
      expect(manifest.version).to eq(manifest.facts.map(&:since).max)
    end

    it "validates against the published schema, and renders the same every time" do
      expect(ApiContract.errors("config-manifest.response", "v1", JSON.parse(manifest.to_json))).to eq([])
      expect(manifest.to_json).to eq(manifest.to_json)
      expect(manifest.etag).to match(/\A\h{64}\z/)
    end

    it "publishes the limits an agent must stay within" do
      expect(manifest.fact("sshd.maxauthtries").as_json).to include("type" => "integer", "minimum" => 0, "maximum" => 1000)
      expect(manifest.fact("sshd.ciphers").as_json).to include("max_items" => 64, "item_max_length" => 256)
      expect(manifest.fact("sshd.loglevel").as_json).to include("max_length" => 16)
      expect(manifest.fact("file:/etc/passwd").as_json.keys).to match_array(%w[key type since description])
    end

    it "lists facts for a report made against an older version only up to that version" do
      expect(manifest.facts_for(manifest.version)).to eq(manifest.facts)
      expect(manifest.facts_for(0)).to eq([])
    end

    it "never names a command: no description or key asks for anything to be run" do
      expect(manifest.facts.map(&:key).grep(/\s|;|\||\$|`/)).to eq([])
    end
  end

  describe "released facts are never removed, retyped, or tightened (docs/operations/config-facts.md)" do
    frozen = YAML.safe_load_file(Rails.root.join("spec/fixtures/config_manifest/frozen_facts.yml")).fetch("facts")

    it "keeps every released fact with its type and since" do
      missing = frozen.reject { |old| manifest.fact(old["key"])&.then { |now| now.type == old["type"] && now.since == old["since"] } }.map { |old| old["key"] }
      expect(missing).to eq([])
    end

    it "keeps every released limit or loosens it" do
      tighter = frozen.flat_map do |old|
        now = manifest.fact(old["key"])
        next [] unless now

        { "minimum" => :<=, "maximum" => :>=, "max_length" => :>=, "max_items" => :>=, "item_max_length" => :>= }.filter_map do |limit, direction|
          next unless old.key?(limit)

          "#{old['key']} #{limit}" unless now.constraints[limit].public_send(direction, old[limit])
        end
      end
      expect(tighter).to eq([])
    end

    it "lists every fact in the manifest at an earlier version, so a new fact must be added to the fixture" do
      released = manifest.facts.select { |f| f.since < manifest.version }.map(&:key)
      expect(released - frozen.map { |f| f["key"] }).to eq([])
    end
  end

  describe "value rules" do
    def errors(key, value) = manifest.fact(key).value_errors(value)

    it "checks strings, integers, booleans, and lists against their limits" do
      expect(errors("sshd.loglevel", "x" * 16)).to eq([])
      expect(errors("sshd.loglevel", "x" * 17)).to eq([ "is longer than 16 characters" ])
      expect(errors("sshd.loglevel", 3)).to eq([ "must be a string" ])
      expect([ errors("sshd.maxauthtries", 0), errors("sshd.maxauthtries", 1000) ]).to eq([ [], [] ])
      expect(errors("sshd.maxauthtries", 1001)).to eq([ "must be from 0 to 1000" ])
      expect(errors("sshd.maxauthtries", "4")).to eq([ "must be an integer" ])
      expect(errors("sshd.maxauthtries", 4.0)).to eq([ "must be an integer" ])
      expect([ errors("sshd.x11forwarding", true), errors("sshd.x11forwarding", false) ]).to eq([ [], [] ])
      expect(errors("sshd.x11forwarding", "no")).to eq([ "must be true or false" ])
      expect(errors("sshd.ciphers", [ "a" ] * 64)).to eq([])
      expect(errors("sshd.ciphers", [ "a" ] * 65)).to eq([ "has more than 64 entries" ])
      expect(errors("sshd.ciphers", [ "a" * 257 ])).to eq([ "has an entry longer than 256 characters" ])
      expect(errors("sshd.ciphers", [ "a", 1 ])).to eq([ "must be a list of strings" ])
      expect(errors("sshd.ciphers", "a")).to eq([ "must be a list of strings" ])
    end

    it "accepts a file's mode, owner, and group, or null for no such file" do
      key = "file:/etc/shadow"
      expect([ errors(key, nil), errors(key, { "mode" => "0640", "owner" => "root", "group" => "shadow" }), errors(key, { "mode" => "640", "owner" => "0", "group" => "42" }) ]).to eq([ [], [], [] ])
      expect(errors(key, { "mode" => "0o640", "owner" => "", "group" => 1 }))
        .to eq([ "mode must be an octal string such as \"0640\"", "owner must be a string of 1 to 64 characters", "group must be a string of 1 to 64 characters" ])
      expect(errors(key, { "mode" => "0640", "owner" => "o" * 65, "group" => "g" })).to eq([ "owner must be a string of 1 to 64 characters" ])
      expect(errors(key, "0640")).to eq([ "must be null (no such file) or an object with mode, owner, and group" ])
    end

    it "accepts a unit's active and enabled words, or null for no such unit" do
      key = "service:ssh.service"
      expect([ errors(key, nil), errors(key, { "active" => "active", "enabled" => "enabled-runtime" }) ]).to eq([ [], [] ])
      expect(errors(key, { "active" => "Active", "enabled" => nil })).to eq([ "active must be a lower-case word", "enabled must be a lower-case word" ])
      expect(errors(key, [])).to eq([ "must be null (no such unit) or an object with active and enabled" ])
    end
  end

  describe "loading" do
    it "accepts the smallest valid manifest, and expands files and services into facts" do
      loaded = load_yaml(base) do |d|
        d["files"] = [ { "path" => "/etc/passwd", "since" => 1, "description" => "Accounts." } ]
        d["services"] = [ { "unit" => "ssh.service", "since" => 1 } ]
      end
      expect(loaded.facts.map(&:key)).to eq([ "file:/etc/passwd", "service:ssh.service", "sshd.loglevel" ])
      expect(loaded.fact("file:/etc/passwd")).to have_attributes(type: "file_attributes", example: described_class::FILE_EXAMPLE)
      expect(loaded.fact("service:ssh.service").description).to include("ssh.service")
      expect(loaded.fact("sshd.loglevel").constraints).to eq("max_length" => 256)
    end

    it "reports every problem at once" do
      error = begin
        load_yaml(base) do |d|
          d["manifest_version"] = 3
          d["facts"] += [ { "key" => "Bad", "type" => "string", "since" => 1, "description" => "x", "example" => "x" },
                          { "key" => "a.b", "type" => "regex", "since" => 1, "description" => "x" },
                          { "key" => "a.c", "type" => "integer", "since" => 0, "description" => "", "minimum" => 1, "max_length" => 3, "example" => "x" },
                          { "key" => "sshd.loglevel", "type" => "string", "since" => 1, "description" => "again", "example" => "x" } ]
          d["files"] = [ { "path" => "etc/passwd", "since" => 1, "description" => "x" } ]
          d["services"] = [ { "unit" => "bad unit", "since" => 1 } ]
        end
      rescue described_class::Invalid => e
        e.message
      end
      expect(error).to include("Bad: key must look like", "a.b: unknown type \"regex\"", "a.c: since must be a positive integer", "a.c: description must be 1 to 512 characters",
                               "a.c: unknown or misplaced fields max_length", "a.c: its example must be an integer", "sshd.loglevel: listed 2 times",
                               "etc/passwd: path must be absolute", "bad unit: unit name is not valid", "manifest_version is 3 but no fact has since 3")
    end

    it "refuses a manifest that is not a mapping, has no version, or has a malformed list" do
      [ [], { "facts" => [] }, { "manifest_version" => 1, "facts" => "no" }, { "manifest_version" => 0, "facts" => [] } ].each do |data|
        expect { load_yaml(data) }.to raise_error(described_class::Invalid), data.inspect
      end
      expect { load_yaml(base) { |d| d["facts"] = [ "text" ] } }.to raise_error(described_class::Invalid, /facts must be a list of mappings/)
    end

    it "refuses an example that its own fact would reject" do
      expect { load_yaml(base) { |d| d["facts"][0]["example"] = "x" * 300 } }.to raise_error(described_class::Invalid, /its example is longer than 256/)
    end

    it "memoises the current manifest until reset" do
      first = described_class.current
      expect(described_class.current).to equal(first)
      described_class.reset!
      expect(described_class.current).not_to equal(first)
    end
  end
end
