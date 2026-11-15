require "rails_helper"
require "rake"

# bin/rails compliance_summaries:check and compliance_summaries:rebuild (#193).
RSpec.describe "compliance_summaries rake tasks" do
  before(:all) { Rails.application.load_tasks if Rake::Task.tasks.none? { |task| task.name == "compliance_summaries:rebuild" } }

  def run(task)
    Rake::Task[task].reenable
    output = StringIO.new
    $stdout = output
    Rake::Task[task].invoke
    output.string
  ensure
    $stdout = STDOUT
  end

  let!(:host) { enrolled_host.first }

  it "says every summary matches, and rebuilds them all" do
    findings!(host, "high")
    expect(run("compliance_summaries:check")).to eq("Every host's compliance summary matches its rows.\n")
    expect(run("compliance_summaries:rebuild")).to eq("Rebuilt the compliance summaries of 1 host.\n")
  end

  it "names the hosts whose summaries differ and exits 1, until they are rebuilt" do
    others = Array.new(21) { create(:host) }
    HostComplianceSummary.where(host_id: [ host, *others ].map(&:id)).update_all(cis_failed: 3)
    expect { run("compliance_summaries:check") }.to raise_error(SystemExit) { |error| expect(error.status).to eq(1) }
                                                .and output(/\A22 hosts differ from their rows \(host ids #{host.id}, .*, \.\.\.\)\. Run bin\/rails compliance_summaries:rebuild\.\n\z/).to_stderr
    expect(run("compliance_summaries:rebuild")).to eq("Rebuilt the compliance summaries of 22 hosts.\n")
    expect(run("compliance_summaries:check")).to start_with("Every host's")
  end
end
