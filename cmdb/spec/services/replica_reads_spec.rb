require "rails_helper"

# Dashboard and report reads from a replica (#198 step 2). The test environment's replica is the test database itself
# (config/database.yml), shared with the writing connection, so the reading role refuses writes as a replica would.
RSpec.describe ReplicaReads do
  after { described_class.reset! }

  def role_inside = described_class.around { ApplicationRecord.current_role }

  it "runs the block on the reading role, with writes refused, once the replica has caught up" do
    expect(described_class.configured?).to be(true)
    expect(role_inside).to eq(:reading)
    expect { described_class.around { HostStatusEvent.where(id: 0).update_all(reason: "x") } }.to raise_error(ActiveRecord::ReadOnlyError)
  end

  it "reads the primary when there is no replica" do
    allow(described_class).to receive(:configured?).and_return(false)
    expect(role_inside).to eq(:writing)
  end

  it "compares the replica's replay position with the primary's WAL position taken first" do
    statements = []
    callback = ->(*, payload) { statements << [ payload[:name], payload[:sql] ] }
    ActiveSupport::Notifications.subscribed(callback, "sql.active_record") { expect(described_class.caught_up?).to be(true) }
    expect(statements.map(&:first)).to eq([ "Replica target", "Replica caught up" ])
    expect(statements.last.last).to match(/NOT pg_is_in_recovery\(\) OR pg_last_wal_replay_lsn\(\) >= '[0-9A-F]+\/[0-9A-F]+'::pg_lsn/)
  end

  describe "a replica that lags" do
    let(:connection) { ApplicationRecord.connection }

    before do
      allow(connection).to receive(:select_value).and_call_original
      allow(Rails.configuration.x).to receive(:replica_max_wait_ms).and_return(50)
    end

    it "waits for it, up to FLEET_REPLICA_MAX_WAIT_MS" do
      answers = [ false, false, true ]
      allow(connection).to receive(:select_value).with(anything, "Replica caught up") { answers.shift }
      expect(role_inside).to eq(:reading)
      expect(answers).to be_empty
    end

    it "reads the primary when it has not caught up in time, and tries it again on the next page" do
      allow(connection).to receive(:select_value).with(anything, "Replica caught up").and_return(false)
      allow(Rails.logger).to receive(:info).and_call_original
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      expect(role_inside).to eq(:writing)
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be_between(0.05, 1)
      expect(described_class.down?).to be_falsey
      expect(Rails.logger).to have_received(:info).with("[replica] not caught up within 50 ms; this page reads the primary")
    end
  end

  describe "a replica that fails" do
    it "is not tried for BACKOFF after the check fails, and pages read the primary meanwhile" do
      allow(ApplicationRecord.connection).to receive(:select_value).and_call_original
      allow(ApplicationRecord.connection).to receive(:select_value).with(anything, "Replica caught up").and_raise(ActiveRecord::ConnectionNotEstablished)
      expect(Rails.logger).to receive(:error).with(/\[replica\] ActiveRecord::ConnectionNotEstablished: pages read the primary for 30 seconds/)
      expect(role_inside).to eq(:writing)
      expect(described_class.down?).to be(true)
      expect(described_class.caught_up?).to be(false)
      travel(described_class::BACKOFF + 1.second) { expect(described_class.down?).to be(false) }
    end

    it "is marked down when it fails while a page reads it, and the error goes on to the page" do
      # Tests share the writing pool with the reading role, so a replica's pool is stood in for.
      pool = instance_double(ActiveRecord::ConnectionAdapters::ConnectionPool, role: :reading)
      expect do
        described_class.around { raise ActiveRecord::ConnectionNotEstablished.new("gone", connection_pool: pool) }
      end.to raise_error(ActiveRecord::ConnectionNotEstablished)
      expect(described_class.down?).to be(true)
    end

    it "is not marked down for another database's connection error" do
      expect do
        described_class.around { raise ActiveRecord::ConnectionNotEstablished.new("queue gone", connection_pool: SolidQueue::Record.connection_pool) }
      end.to raise_error(ActiveRecord::ConnectionNotEstablished)
      expect(described_class.down?).to be_falsey
    end
  end
end
