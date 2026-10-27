require "rails_helper"
require "rake"

RSpec.describe "settings rake tasks (P1-S09)" do
  before(:all) { Rails.application.load_tasks if Rake::Task.tasks.none? { |task| task.name == "settings:liveness" } }

  def run(task, env = {})
    Rake::Task[task].reenable
    original = env.keys.to_h { |key| [ key, ENV[key] ] }
    env.each { |key, value| ENV[key] = value }
    output = StringIO.new
    $stdout = output
    Rake::Task[task].invoke
    output.string
  ensure
    $stdout = STDOUT
    original&.each { |key, value| ENV[key] = value }
  end

  it "shows and changes the liveness thresholds" do
    expect(run("settings:show")).to include("liveness.online_threshold_minutes = 3", "liveness.stale_threshold_minutes = 15")
    expect(run("settings:liveness", "ONLINE_MINUTES" => "5", "STALE_MINUTES" => "30")).to include("Online under 5 minutes, stale under 30")
    expect(Setting.liveness_thresholds).to eq(online: 5.minutes, stale: 30.minutes)
  end

  it "explains invalid or missing values" do
    expect { expect { run("settings:liveness", "ONLINE_MINUTES" => "20", "STALE_MINUTES" => "10") }.to output(/shorter than/).to_stderr }.to raise_error(SystemExit)
    expect { expect { run("settings:liveness", "ONLINE_MINUTES" => nil, "STALE_MINUTES" => nil) }.to output(/Usage/).to_stderr }.to raise_error(SystemExit)
  end
end
