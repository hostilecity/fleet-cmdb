# Run with bin/benchmark (or bin/rails runner script/benchmark/run.rb COMMAND [options]). See fleet_benchmark.rb.
$stdout.sync = true
require_relative "fleet_benchmark"

exit FleetBenchmark::CLI.run(ARGV)
