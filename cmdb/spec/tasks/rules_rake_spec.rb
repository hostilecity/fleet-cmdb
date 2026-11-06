require "rails_helper"
require "rake"

RSpec.describe "rules rake tasks (P2-S04)" do
  before(:all) { Rails.application.load_tasks if Rake::Task.tasks.none? { |task| task.name == "rules:import" } }

  def run(task, env = {})
    Rake::Task[task].reenable
    env.each { |key, value| ENV[key] = value }
    output = StringIO.new
    $stdout = output
    Rake::Task[task].invoke
    output.string
  ensure
    $stdout = STDOUT
    env.each_key { |key| ENV.delete(key) }
  end

  let(:example) { Rails.root.join("../docs/api/rules/v1/examples/valid/every-operator.json").to_s }

  def write(text) = Pathname(Dir.mktmpdir).join("rules.yml").tap { |path| path.write(text) }.to_s

  it "imports a file and prints what changed, then lists the rules" do
    output = run("rules:import", "FILE" => example)
    expect(output).to include("Created: 11: ssh-root-login-off, ", "Versioned: 0", "Unchanged: 0", "Disabled: 0")
    expect(run("rules:import", "FILE" => example)).to include("Created: 0", "Unchanged: 11")
    expect(run("rules:list")).to include("ssh-root-login-off  v1  enabled  high  sshd.permitrootlogin", "timesync-running  v1  disabled  medium  service:chrony.service")
    expect(AuditEntry.where(action: Audit::Actions::RULE_CREATED).pluck(:actor_type).uniq).to eq([ "system" ])
  end

  it "disables rules missing from the file only with DISABLE_MISSING=1" do
    run("rules:import", "FILE" => example)
    empty = write({ "format_version" => 1, "rules" => [] }.to_yaml)
    expect(run("rules:import", "FILE" => empty)).to include("Disabled: 0")
    expect(run("rules:import", "FILE" => empty, "DISABLE_MISSING" => "1")).to include("Disabled: 10: ")
  end

  it "aborts with every problem and changes nothing for an invalid file" do
    bad = write("format_version: 2\nrules: nope\n")
    expect { expect { run("rules:import", "FILE" => bad) }.to output(/was not imported; nothing changed\. 2 problem\(s\):\n  \/format_version/).to_stderr }.to raise_error(SystemExit)
    expect(CisRule.count).to eq(0)
  end

  it "aborts without FILE, or with a file it cannot read" do
    expect { expect { run("rules:import") }.to output(/Usage: bin\/rails rules:import/).to_stderr }.to raise_error(SystemExit)
    expect { expect { run("rules:import", "FILE" => "/nonexistent/rules.yml") }.to output(/Cannot read \/nonexistent\/rules.yml/).to_stderr }.to raise_error(SystemExit)
  end

  it "says when there are no rules" do
    expect(run("rules:list")).to include("No rules.")
  end
end
