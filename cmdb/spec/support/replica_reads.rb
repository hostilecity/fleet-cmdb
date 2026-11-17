# ReplicaReads marks the replica down for 30 s after a database error during its check (#198). A spec that breaks the
# database on purpose would otherwise send every later page in the run to the primary, and the listed pages would no
# longer run with writes refused. Each example starts with the replica up.
RSpec.configure do |config|
  config.before { ReplicaReads.reset! }
end
