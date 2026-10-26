# Guards the agent API contract in docs/api (P0-CONTRACT, FR-S.2, NFR-5). See docs/api/README.md.
require "rails_helper"

RSpec.describe "Agent API contract (docs/api)" do
  versions = ApiContract.versions
  examples = ApiContract.examples

  it "has at least one schema version" do
    expect(versions).to include("v1")
  end

  versions.each do |version|
    ApiContract.schema_names(version).each do |name|
      describe "#{version}/#{name}" do
        let(:schema) { ApiContract.schema(name, version) }
        let(:valid) { examples.select { |e| e.version == version && e.schema_name == name && e.kind == "valid" } }
        let(:invalid) { examples.select { |e| e.version == version && e.schema_name == name && e.kind == "invalid" } }

        it "is a valid draft 2020-12 schema" do
          expect(schema["$schema"]).to eq("https://json-schema.org/draft/2020-12/schema")
          expect(JSONSchemer.validate_schema(schema).map { |e| e.fetch("error") }).to eq([])
        end

        it "has valid and invalid examples" do
          expect(valid).not_to be_empty
          expect(invalid).not_to be_empty
        end

        it "has every declared property in at least one valid example" do
          present = valid.map { |e| ApiContract.present_paths(e.data) }.reduce(Set.new, :|)
          missing = ApiContract.declared_paths(schema) - present
          expect(missing.to_a.sort).to eq([]), "add a valid example in docs/api/examples/#{version}/#{name}/valid/ " \
                                               "that uses: #{missing.to_a.sort.join(', ')}"
        end

        it "declares every property used by its valid examples" do
          declared = ApiContract.declared_paths(schema)
          valid.reject { |e| e.name.start_with?("unknown-field-") }.each do |example|
            undeclared = ApiContract.present_paths(example.data) - declared
            expect(undeclared.to_a.sort).to eq([]), "#{example} uses keys the schema does not declare"
          end
        end
      end
    end
  end

  examples.each do |example|
    describe example.to_s do
      it "has a matching schema" do
        expect(ApiContract.schema_path(example.schema_name, example.version)).to exist
      end

      if example.kind == "valid"
        it "validates" do
          expect(ApiContract.errors(example.schema_name, example.version, example.data)).to eq([])
        end
      else
        it "is rejected" do
          expect(ApiContract.errors(example.schema_name, example.version, example.data)).not_to be_empty
        end
      end

      it "contains no real hostnames, addresses, or credentials" do
        expect(ApiContract.real_data_problems(example.data)).to eq([])
      end
    end
  end

  describe ApiContract do
    it "finds declared paths through items, $ref, and combinators" do
      schema = {
        "$defs" => { "disk" => { "properties" => { "mount" => {} } } },
        "properties" => {
          "disks" => { "items" => { "$ref" => "#/$defs/disk" } },
          "os" => { "anyOf" => [ { "properties" => { "id" => {} } } ] }
        }
      }
      expect(ApiContract.declared_paths(schema)).to eq(Set["disks", "disks[].mount", "os", "os.id"])
    end

    it "flags real-looking data and accepts example data" do
      expect(ApiContract.real_data_problems({ "hostname" => "vm-01.example.lan", "addresses" => [ "192.0.2.1/24", "2001:db8::1/64" ],
                                              "token" => "EXAMPLE-token", "time" => "2026-01-01T12:00:00Z" })).to eq([])
      problems = ApiContract.real_data_problems({ "hostname" => "nas.home.arpa", "addresses" => [ "10.0.0.5/24", "fd00::5/64" ],
                                                  "credential" => "abc.def" })
      expect(problems).to include(/nas\.home\.arpa/, /10\.0\.0\.5/, /fd00::5/, /credential value/)
    end

    it "flags single-label hostnames under a hostname key" do
      expect(ApiContract.real_data_problems({ "hostname" => "nas" })).to include(/hostname "nas"/)
      expect(ApiContract.real_data_problems({ "hostname" => "vm-01.example.lan" })).to eq([])
      expect(ApiContract.real_data_problems({ "hostname" => "vm-01.test" })).to eq([])
    end
  end
end
