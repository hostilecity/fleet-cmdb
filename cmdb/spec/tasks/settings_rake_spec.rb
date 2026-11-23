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

  it "changes the retention window and explains invalid or missing values (P1-S10)" do
    expect(run("settings:show")).to include("retention.days = 90")
    expect(run("settings:retention", "DAYS" => "45")).to include("kept for at least 45 days, report ids for at least 7. Audit entries are never pruned.")
    expect(Setting.retention_window).to eq(45.days)
    expect { expect { run("settings:retention", "DAYS" => "2") }.to output(/Not changed: Enter a whole number of days from 7 to 3650/).to_stderr }.to raise_error(SystemExit)
    expect { expect { run("settings:retention", "DAYS" => nil) }.to output(/Usage/).to_stderr }.to raise_error(SystemExit)
    expect(Setting.retention_window).to eq(45.days)
  end

  it "changes the vulnerability badge settings, one or both, and explains invalid or missing values (VT-SCORES #262)" do
    expect(run("settings:show")).to include("vulnerabilities.badge_report_max_age_days = 3", "vulnerabilities.run_grace_days = 7")
    expect(run("settings:vulnerability_badges", "GRACE_DAYS" => "10")).to include("older than 3 days; a run is kept through a new fixable critical for 10 days.")
    expect(run("settings:vulnerability_badges", "REPORT_DAYS" => "5", "GRACE_DAYS" => "10")).to include("older than 5 days")
    expect(Setting.vulnerability_badges).to eq(report_max_age: 5.days, run_grace: 10.days)
    expect(AuditEntry.where(action: Audit::Actions::SETTING_CHANGED).count).to eq(2) # the unchanged grace is not audited again
    expect { expect { run("settings:vulnerability_badges", "REPORT_DAYS" => "31") }.to output(/Not changed: Enter a whole number of days from 1 to 30/).to_stderr }.to raise_error(SystemExit)
    expect { expect { run("settings:vulnerability_badges") }.to output(/Usage/).to_stderr }.to raise_error(SystemExit)
  end
end
