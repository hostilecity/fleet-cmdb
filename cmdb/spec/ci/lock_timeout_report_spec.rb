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

  # The real query, run as the reporter runs it, but only its client sessions count here: an autovacuum worker may hold
  # locks in this database at any moment (#310), and the report rightly lists it, labelled by its backend type. The one
  # session holding a lock is the timed-out one, which the report leaves out; so is the reporter's own session.
  it "leaves out the timed-out session and its own, says so when no other session holds a lock, and records a failure to look instead of raising" do
    allow(described_class).to receive(:holders).and_wrap_original do |original, *args|
      original.call(*args).select { |row| row["backend_type"] == "client backend" }
    end
    timed_out = separate_session
    timed_out.execute("BEGIN")
    timed_out.execute("LOCK TABLE operators IN ACCESS EXCLUSIVE MODE")
    timed_out_pid = timed_out.select_value("SELECT pg_backend_pid()")
    described_class.record(ApplicationRecord.connection_db_config.configuration_hash, timed_out_pid, "SELECT 1")
    described_class.record({ host: "/nonexistent-socket-dir", database: "none" }, nil, "SELECT 2")
    lines = File.readlines(file, chomp: true)
    expect(lines[0]).to end_with("(pid #{timed_out_pid}): SELECT 1")
    expect(lines[1]).to eq("  no other session holds a lock in this database now")
    expect(lines[2]).to match(/could not list the lock holders: PG::ConnectionBad/)
  ensure
    timed_out&.execute("ROLLBACK")
    timed_out&.disconnect!
  end
end
