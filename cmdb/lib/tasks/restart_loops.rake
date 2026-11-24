# The fleet filter's restart-loop column after a change of the limit (#251, review of #307, S1). See
# docs/operations/configuration.md, FLEET_RESTART_LOOP_RESTARTS.
namespace :restart_loops do
  desc "Store each host's restart-loop time again for FLEET_RESTART_LOOP_RESTARTS as now set (after changing it)"
  task refresh: :environment do
    changed = Host.refresh_restart_loops!
    puts "Restart loops: #{changed} host#{'s' unless changed == 1} updated for more than #{Rollouts.restart_loop.limit} restarts."
  end
end
