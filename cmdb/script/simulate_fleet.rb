# Run with bin/simulate-fleet (or bin/rails runner script/simulate_fleet.rb [options]). See lib/fleet_simulator.rb.
$stdout.sync = true
require Rails.root.join("lib/fleet_simulator").to_s

exit FleetSimulator::CLI.run(ARGV)
