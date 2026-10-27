require "rails_helper"
require "rake"

RSpec.describe "operators rake tasks (FR-S.4)" do
  before(:all) { Rails.application.load_tasks if Rake::Task.tasks.none? { |task| task.name == "operators:allow" } }

  def run(task, email)
    Rake::Task[task].reenable
    original = ENV["EMAIL"]
    ENV["EMAIL"] = email
    output = StringIO.new
    $stdout = output
    Rake::Task[task].invoke
    output.string
  ensure
    $stdout = STDOUT
    ENV["EMAIL"] = original
  end

  it "adds the first operator, lists, and removes, auditing each change" do
    expect(run("operators:list", nil)).to include("The allowlist is empty")
    expect(run("operators:allow", " First@Example.com ")).to include("Allowed first@example.com.")
    expect(OperatorAllowlistEntry.allowed?("first@example.com")).to be(true)
    expect(run("operators:list", nil)).to include("first@example.com  never signed in")
    expect(run("operators:disallow", "first@example.com")).to include("Removed first@example.com.")
    expect(OperatorAllowlistEntry.count).to eq(0)
    expect(AuditEntry.where(action: [ Audit::Actions::OPERATOR_ALLOWED, Audit::Actions::OPERATOR_DISALLOWED ]).pluck(:action, :actor_type))
      .to eq([ [ "operator.allowed", "system" ], [ "operator.disallowed", "system" ] ])
  end

  it "rejects duplicates, invalid emails, unknown removals, and a missing EMAIL" do
    run("operators:allow", "first@example.com")
    expect { expect { run("operators:allow", "first@example.com") }.to output(/has already been taken/).to_stderr }.to raise_error(SystemExit)
    expect { expect { run("operators:allow", "not-an-email") }.to output(/Email is invalid/).to_stderr }.to raise_error(SystemExit)
    expect { expect { run("operators:disallow", "nobody@example.com") }.to output(/not on the allowlist/).to_stderr }.to raise_error(SystemExit)
    expect { expect { run("operators:allow", nil) }.to output(/Usage/).to_stderr }.to raise_error(SystemExit)
  end
end
