# Guards the task catalog file in docs/api/tasks (FR-3.1, P3-S01, AC-3.7): the server reads the one shared file,
# the file passes the catalog lint, and every example the lint must accept or reject does what its name says.
# The agent compiles in the same file (P3-A01, #34); its own test checks the bytes it embeds against it.
require "rails_helper"

RSpec.describe "Task catalog file (docs/api/tasks)" do
  root = Rails.root.join("../docs/api/tasks").expand_path
  examples = root.glob("examples/{valid,invalid}/*.json").sort.map { |path| [ path.parent.basename.to_s, path ] }

  it "is read by the server from docs/api/tasks, where the agent reads it too" do
    expect(TaskCatalog::PATH).to eq(root.join("task-catalog.json"))
    expect(TaskCatalog::SCHEMA_PATH).to eq(root.join("task-catalog.schema.json"))
    expect(TaskCatalog.current.digest).to eq(Digest::SHA256.hexdigest(root.join("task-catalog.json").binread))
  end

  it "has a valid draft 2020-12 schema" do
    schema = JSON.parse(TaskCatalog::SCHEMA_PATH.read)
    expect(schema["$schema"]).to eq("https://json-schema.org/draft/2020-12/schema")
    expect(JSONSchemer.validate_schema(schema).map { |e| e.fetch("error") }).to eq([])
  end

  it "passes the catalog lint" do
    expect(TaskCatalog.lint(TaskCatalog::PATH.binread)).to eq([])
  end

  it "has the initial entries (FR-3.1, DEC-13, DEC-15, DEC-16)" do
    catalog = TaskCatalog.current
    expect(catalog.version).to eq(1)
    expect(catalog.types).to eq(%w[refresh_reports restart_service apply_package_updates])
    expect(catalog.entries.map { |entry| [ entry.type, entry.privilege, entry.enabled_by_default, entry.interruptible ] }).to eq([
      [ "refresh_reports", "read_only", true, true ],
      [ "restart_service", "service_manager", false, false ],
      [ "apply_package_updates", "package_manager", false, false ]
    ])
    expect(catalog.entry("apply_package_updates").timeout).to eq(60.minutes) # DEC-16
    expect(catalog.entry("apply_package_updates").parameters).to eq([]) # DEC-16: no parameters in the first release
    expect(catalog.entries.map(&:expiry).uniq).to eq([ 24.hours ]) # DEC-14
    expect(catalog.entry("restart_service").parameter_names).to eq(%w[service])
  end

  it "has valid and invalid examples" do
    expect(examples.map(&:first).uniq).to contain_exactly("valid", "invalid")
  end

  examples.each do |kind, path|
    it "#{kind}/#{path.basename} #{kind == 'valid' ? 'passes' : 'fails'} the catalog lint" do
      problems = TaskCatalog.lint(path.binread)
      if kind == "valid"
        expect(problems).to eq([])
      else
        expect(problems).not_to be_empty
      end
    end
  end

  # The agent half of "server and agent catalogs are identical" (P3-A01, #34): wherever the agent compiles in the
  # catalog, it must be this file, and nothing in the repository may hold a second copy that could drift.
  it "is the only catalog in the repository, and the only one the agent compiles in" do
    repo = Rails.root.join("..").expand_path
    copies = repo.glob("{docs,agent/src,agent/tests,agent/build.rs,cmdb/app,cmdb/lib,cmdb/config,ops}/**/*catalog*.{json,yml,yaml,toml}")
    expect(copies.map { |path| path.relative_path_from(repo).to_s }.reject { |path| path.start_with?("docs/api/tasks/") }).to eq([])
    embedded = repo.glob("agent/{src,tests}/**/*.rs").push(repo.join("agent/build.rs")).select(&:file?).flat_map do |source|
      source.read.scan(/include_(?:str|bytes)!\(\s*"([^"]*task-catalog[^"]*)"/).flatten.map { |path| source.dirname.join(path).expand_path }
    end
    expect(embedded.uniq - [ TaskCatalog::PATH ]).to eq([])
  end

  it "keeps real hostnames and addresses out of the file" do
    text = TaskCatalog::PATH.read
    expect(text).not_to match(/\b\d{1,3}(\.\d{1,3}){3}\b/)
    expect(text.scan(/\b[a-z0-9-]+\.(?:com|net|org|lan|io)\b/)).to eq([])
  end
end
