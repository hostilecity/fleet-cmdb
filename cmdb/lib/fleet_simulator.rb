# Fleet simulator (P1-O04, NFR-3, AC-1.2): fake hosts that enroll and report through the real agent API of a
# running server, for development seed data, the 50-host load check, and an end-to-end liveness check with
# the real timers. Development and test tooling only: the application never loads it (config/application.rb
# keeps it out of autoloading), and the command refuses to run in production.
#
#   bin/simulate-fleet --help
#
# See docs/operations/fleet-simulator.md.
module FleetSimulator
  # Every simulated host is named and tagged with this, so they are easy to find and filter in the dashboard.
  NAME_PREFIX = "sim-"
  TAG = "simulator"
end

require_relative "fleet_simulator/options"
require_relative "fleet_simulator/clock"
require_relative "fleet_simulator/stats"
require_relative "fleet_simulator/sim_host"
require_relative "fleet_simulator/payloads"
require_relative "fleet_simulator/http_transport"
require_relative "fleet_simulator/operator_cookie"
require_relative "fleet_simulator/enroller"
require_relative "fleet_simulator/runner"
require_relative "fleet_simulator/fleet_list_probe"
require_relative "fleet_simulator/liveness_check"
require_relative "fleet_simulator/report"
require_relative "fleet_simulator/cli"
