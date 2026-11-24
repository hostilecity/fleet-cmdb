require "rails_helper"
require "rake"

# bin/rails restart_loops:refresh, after FLEET_RESTART_LOOP_RESTARTS changes (#251, review of #307, S1).
RSpec.describe "restart_loops rake task" do
  before(:all) do
    Rails.application.load_tasks if Rake::Task.tasks.none? { |task| task.name == "restart_loops:refresh" }
  end

  it "stores each host's restart-loop time again for the limit as now set, and says how many changed" do
    host, = enrolled_host
    times = [ 1.minute.ago, 2.minutes.ago, 3.minutes.ago ]
    host.update_columns(agent_recent_restarts: times, agent_restart_loop_at: nil)
    Rails.configuration.x.restart_loop.limit = 2
    Rake::Task["restart_loops:refresh"].reenable
    expect { Rake::Task["restart_loops:refresh"].invoke }.to output("Restart loops: 1 host updated for more than 2 restarts.\n").to_stdout
    expect(host.reload.agent_restart_loop_at).to be_within(0.001).of(times[2])
    Rake::Task["restart_loops:refresh"].reenable
    expect { Rake::Task["restart_loops:refresh"].invoke }.to output("Restart loops: 0 hosts updated for more than 2 restarts.\n").to_stdout
  end
end
