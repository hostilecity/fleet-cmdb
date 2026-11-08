require "rails_helper"

RSpec.describe TaskCatalog do
  examples = Rails.root.join("../docs/api/tasks/examples")

  def lint_messages(name) = TaskCatalog.lint(Rails.root.join("../docs/api/tasks/examples/invalid/#{name}.json").binread).map(&:to_s)

  def catalog_with(parameters, required: [])
    {
      "format_version" => 1, "catalog_version" => 1,
      "tasks" => [ { "type" => "example_task", "name" => "Example", "description" => "Runs nothing.", "since" => 1,
                     "privilege" => "read_only", "interruptible" => true, "enabled_by_default" => true,
                     "timeout_seconds" => 60, "expiry_seconds" => 3600,
                     "parameters" => { "type" => "object", "additionalProperties" => false, "properties" => parameters, "required" => required } } ]
    }
  end

  def pattern_problems(pattern) = described_class.strict_pattern_problems(pattern)

  describe ".lint (P3-S01 acceptance criteria)" do
    it "rejects a free-form string parameter" do
      expect(lint_messages("free-form-string")).to include(a_string_matching(/needs an enum or a pattern; free-form strings are not allowed/))
    end

    it "rejects a parameter named command, and other command-like names" do
      expect(lint_messages("command-parameter")).to include(a_string_matching(%r{/tasks/0/parameters/properties/command}))
      %w[cmd-in-a-parameter-name args-parameter path-parameter env-parameter].each do |name|
        expect(lint_messages(name)).not_to be_empty, name
      end
    end

    it "rejects a command field anywhere in an entry" do
      expect(lint_messages("command-field-on-a-task")).to include(a_string_matching(/command/))
    end

    it "rejects additionalProperties true, or left out" do
      expect(lint_messages("additional-properties-true")).to include(a_string_matching(%r{/tasks/0/parameters/additionalProperties}))
      expect(lint_messages("additional-properties-missing")).not_to be_empty
    end

    it "rejects lists, objects, unbounded integers, and defaults" do
      %w[list-parameter object-parameter unbounded-integer default-value pattern-properties].each do |name|
        expect(lint_messages(name)).not_to be_empty, name
      end
    end
  end

  describe ".lint, beyond the schema" do
    it "names each semantic problem" do
      expect(lint_messages("duplicate-type")).to eq([ "/tasks: example_task is listed 2 times" ])
      expect(lint_messages("catalog-version-above-since")).to eq([ "/catalog_version: is 2 but the highest since is 1; they must be equal" ])
      expect(lint_messages("risky-type-enabled-by-default")).to eq([ "/tasks/0/enabled_by_default: only read_only task types may be enabled by default (DEC-14)" ])
      expect(lint_messages("required-not-a-parameter")).to eq([ "/tasks/0/parameters/required: names name, which is not a parameter" ])
      expect(lint_messages("integer-minimum-above-maximum")).to eq([ "/tasks/0/parameters/properties/count: minimum is above maximum" ])
      expect(lint_messages("min-length-above-max-length")).to eq([ "/tasks/0/parameters/properties/name: minLength is above maxLength" ])
      expect(lint_messages("enum-outside-pattern")).to eq([ "/tasks/0/parameters/properties/name/enum/0: does not fit the parameter's own length or pattern" ])
    end

    it "rejects duplicate keys, which the agent and the server might read differently" do
      expect(lint_messages("duplicate-key")).to match([ a_string_starting_with("/: is not valid JSON (duplicate key") ])
    end

    it "rejects text that is not UTF-8 or is too large" do
      expect(described_class.lint("{\"a\": \"\xff\"}".b).map(&:to_s)).to eq([ "/: is not UTF-8" ])
      expect(described_class.lint(" " * (TaskCatalog::MAX_BYTES + 1)).map(&:to_s)).to eq([ "/: is larger than #{TaskCatalog::MAX_BYTES} bytes" ])
    end

    it "checks command-like names even if the schema were loosened" do
      schema = JSON.parse(TaskCatalog::SCHEMA_PATH.read)
      schema["$defs"]["parameter_name"].delete("allOf")
      allow(described_class).to receive(:schemer).and_return(JSONSchemer.schema(schema, regexp_resolver: "ecma"))
      text = JSON.generate(catalog_with({ "shell" => { "type" => "boolean", "description" => "Whether." } }))
      expect(described_class.lint(text).map(&:to_s)).to eq([ "/tasks/0/parameters/properties/shell: the name shell suggests a command, its arguments or environment, or a path" ])
    end

    it "checks closed schemas and string rules even if the schema were loosened" do
      schema = JSON.parse(TaskCatalog::SCHEMA_PATH.read)
      schema["$defs"]["parameters"]["properties"]["additionalProperties"] = { "type" => "boolean" }
      schema["$defs"]["string_parameter"].delete("anyOf")
      schema["$defs"]["parameter"] = { "type" => "object" }
      allow(described_class).to receive(:schemer).and_return(JSONSchemer.schema(schema, regexp_resolver: "ecma"))
      data = catalog_with({ "name" => { "type" => "string", "description" => "A name.", "maxLength" => 8 },
                            "items" => { "type" => "array", "description" => "Items." } })
      data["tasks"][0]["parameters"]["additionalProperties"] = true
      expect(described_class.lint(JSON.generate(data)).map(&:to_s)).to contain_exactly(
        "/tasks/0/parameters/additionalProperties: must be false",
        "/tasks/0/parameters/properties/name: a string parameter needs an enum or a pattern; free-form strings are not allowed",
        "/tasks/0/parameters/properties/items/type: must be string, integer, or boolean"
      )
    end
  end

  describe ".strict_pattern_problems" do
    it "accepts strict patterns" do
      [ "^[A-Za-z0-9][A-Za-z0-9_.@-]{0,247}\\.service$", "^(quick|full)$", "^\\d+(\\.\\d+)?$", "^a\\-b\\+c*$" ].each do |pattern|
        expect(pattern_problems(pattern)).to eq([]), pattern
      end
    end

    it "rejects wildcards, negations, special groups, escapes, and characters outside the safe set" do
      expect(pattern_problems("[a-z]+")).to eq([ "must start with ^ and end with $" ])
      expect(pattern_problems("^[a-z]+\\$")).to eq([ "must start with ^ and end with $" ])
      expect(pattern_problems("^.+$")).to eq([ "uses . outside a character class, which matches any character" ])
      expect(pattern_problems("^[^a]+$")).to include("uses a negated character class")
      expect(pattern_problems("^(?:a)$")).to include("uses a special group")
      expect(pattern_problems("^\\w+$")).to eq([ "uses the escape \\w; only \\. \\- \\+ and \\d are allowed" ])
      expect(pattern_problems("^[a-z/]+$")).to eq([ "a character class may hold only letters, digits, and _ . @ + -, not \"/\"" ])
      expect(pattern_problems("^a b$")).to eq([ "may only match letters, digits, and _ . @ + -, not \" \"" ])
      expect(pattern_problems("^[a-z$")).to eq([ "has a character class that is not closed" ])
      expect(pattern_problems("^(a$")).to match([ a_string_starting_with("does not compile") ])
    end
  end

  describe TaskCatalog::Entry do
    let(:restart) { TaskCatalog.current.entry("restart_service") }
    let(:entry) { TaskCatalog.send(:build, JSON.parse(examples.join("valid/every-parameter-type.json").read), "digest").entry("example_task") }

    def pointers(errors) = errors.map { |error| error.values_at("pointer", "problem") }

    it "accepts parameters that fit the schema" do
      expect(restart.parameter_errors({ "service" => "nginx.service" })).to eq([])
      expect(restart.valid_parameters?({ "service" => "php8.4-fpm.service" })).to be(true)
      expect(TaskCatalog.current.entry("refresh_reports").parameter_errors({})).to eq([])
      expect(entry.parameter_errors({ "unit" => "a.service", "mode" => "full", "level" => "low", "count" => 10, "dry_run" => false, "version" => "1.2+b1" })).to eq([])
    end

    it "rejects extra fields, including command-like ones, without echoing their values" do
      errors = restart.parameter_errors({ "service" => "nginx.service", "command" => "rm -rf /", "a/b~" => 1 })
      expect(pointers(errors)).to eq([ [ "/a~1b~0", "is not a parameter of restart_service" ], [ "/command", "is not a parameter of restart_service" ] ])
      expect(errors.to_s).not_to include("rm -rf")
      expect(pointers(TaskCatalog.current.entry("apply_package_updates").parameter_errors({ "scope" => "security" })))
        .to eq([ [ "/scope", "is not a parameter of apply_package_updates" ] ])
    end

    it "rejects missing, wrongly typed, oversize, out-of-pattern, and out-of-enum values" do
      expect(pointers(restart.parameter_errors({}))).to eq([ [ "/service", "is required" ] ])
      expect(pointers(restart.parameter_errors({ "service" => 1 }))).to eq([ [ "/service", "must be a string" ] ])
      expect(pointers(restart.parameter_errors({ "service" => "#{'a' * 250}.service" }))).to eq([ [ "/service", "must be at most 256 characters" ] ])
      expect(pointers(restart.parameter_errors({ "service" => ".service" }))).to eq([ [ "/service", "must be at least 9 characters" ] ])
      [ "nginxxxxx", "-x.service", "nginx.service; reboot", "a b.service", "../x.service", "nginx.service\n", "nginx.socket" ].each do |value|
        expect(pointers(restart.parameter_errors({ "service" => value }))).to eq([ [ "/service", "does not have the required form" ] ]), value
      end
      expect(pointers(entry.parameter_errors({ "unit" => "a.service", "mode" => "fast", "count" => 11, "dry_run" => "no", "level" => true })))
        .to eq([ [ "/mode", "must be one of quick, full" ], [ "/level", "must be a string" ], [ "/count", "must be from 1 to 10" ], [ "/dry_run", "must be true or false" ] ])
      expect(pointers(entry.parameter_errors({ "unit" => "a.service", "mode" => "full", "count" => 1.0 }))).to eq([ [ "/count", "must be a whole number" ] ])
    end

    it "rejects anything but an object with string keys, and oversize parameters as a whole" do
      [ nil, [], "service=nginx.service", { service: "nginx.service" } ].each do |params|
        expect(pointers(restart.parameter_errors(params))).to eq([ [ "", "must be an object" ] ]), params.inspect
      end
      expect(pointers(restart.parameter_errors({ "x" * 5000 => 1 }))).to eq([ [ "", "must be at most 4096 bytes as JSON" ] ])
    end
  end

  describe TaskCatalog::Catalog do
    it "raises UnknownType for a type it does not have" do
      expect(TaskCatalog.current.type?("run_shell")).to be(false)
      expect { TaskCatalog.current.entry("run_shell") }.to raise_error(TaskCatalog::UnknownType, '"run_shell" is not in the task catalog')
    end

    it "is frozen, so nothing can add an entry at runtime" do
      expect(TaskCatalog.current).to be_frozen
      expect(TaskCatalog.current.entries).to be_frozen
    end
  end

  describe ".load" do
    after { described_class.reset! }

    it "raises with every problem listed for a file that fails the lint" do
      expect { described_class.load(examples.join("invalid/duplicate-type.json")) }
        .to raise_error(TaskCatalog::Invalid, /duplicate-type\.json: \/tasks: example_task is listed 2 times/)
    end

    it "loads the shared file once" do
      described_class.reset!
      expect(described_class.current).to be(described_class.current)
    end
  end
end
