require "rails_helper"

# #296: a lock timeout in the suite records who held locks in the test database at that moment
# (spec/support/lock_timeout_report.rb).
RSpec.describe LockTimeoutReport do
  self.use_transactional_tests = false # the holder must commit nothing and the waiter must really wait

  let(:file) { Rails.root.join("tmp/rspec/lock-timeouts-spec-#{SecureRandom.hex(4)}.log").to_s }

  around do |example|
    saved = described_class.path
    described_class.path = file
    example.run
  ensure
    described_class.path = saved
    FileUtils.rm_f(file)
  end

  it "names the session holding the lock, its lock, and the statement that gave up" do
    holder = separate_session
    holder.execute("BEGIN")
    holder.execute("LOCK TABLE operators IN ACCESS EXCLUSIVE MODE")
    holder_pid = holder.select_value("SELECT pg_backend_pid()")
    expect do
      ApplicationRecord.transaction do
        ApplicationRecord.connection.execute("SET LOCAL lock_timeout = '50ms'")
        Operator.count
      end
    end.to raise_error(ActiveRecord::LockWaitTimeout)
    report = File.read(file)
    expect(report).to include("lock_timeout_report_spec.rb", 'SELECT COUNT(*) FROM "operators"')
    expect(report).to match(/^  #{holder_pid} \| client backend \| idle in transaction \| relation \| AccessExclusiveLock \| operators \|/)
  ensure
    holder&.execute("ROLLBACK")
    holder&.disconnect!
  end

  it "says so when nothing else holds a lock, and records a failure to look instead of raising" do
    described_class.record(ApplicationRecord.connection_db_config.configuration_hash, nil, "SELECT 1")
    described_class.record({ host: "/nonexistent-socket-dir", database: "none" }, nil, "SELECT 2")
    lines = File.readlines(file, chomp: true)
    expect(lines[0]).to end_with("(pid ): SELECT 1")
    expect(lines[1]).to eq("  no other session holds a lock in this database now")
    expect(lines[2]).to match(/could not list the lock holders: PG::ConnectionBad/)
  end
end
