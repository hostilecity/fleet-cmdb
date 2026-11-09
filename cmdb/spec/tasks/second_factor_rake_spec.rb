require "rails_helper"
require "rake"

# The lost-authenticator recovery (P3-S09, ADR 0006): bin/rails second_factor:reset, from the console only, audited.
RSpec.describe "second_factor rake tasks" do
  before(:all) { Rails.application.load_tasks if Rake::Task.tasks.none? { |task| task.name == "second_factor:reset" } }

  let(:operator) { create(:operator, email: "example.operator@example.com") }

  def run(*args, email: nil)
    Rake::Task["second_factor:reset"].reenable
    original = ENV["EMAIL"]
    ENV["EMAIL"] = email
    output = StringIO.new
    $stdout = output
    Rake::Task["second_factor:reset"].invoke(*args)
    output.string
  ensure
    $stdout = STDOUT
    ENV["EMAIL"] = original
  end

  it "resets an operator's second factor with EMAIL= or as an argument, and audits it as the system" do
    enrol_second_factor(operator)
    expect(run(email: "Example.Operator@example.com")).to include("Reset the second factor of example.operator@example.com.")
    expect(operator.reload.second_factor).to be_nil
    enrol_second_factor(operator)
    expect(run("example.operator@example.com")).to include("Reset the second factor")
    expect(AuditEntry.where(action: Audit::Actions::SECOND_FACTOR_RESET).pluck(:actor_type, :target_id)).to eq([ [ "system", operator.id ] ] * 2)
  end

  it "says what is wrong when there is nothing to reset" do
    expect { expect { run(email: operator.email) }.to output(/Nothing reset: example.operator@example.com has no second factor/).to_stderr }.to raise_error(SystemExit)
    expect { expect { run }.to output(/Usage/).to_stderr }.to raise_error(SystemExit)
  end
end
