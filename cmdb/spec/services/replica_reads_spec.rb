require "rails_helper"
require "open3"

# Dashboard and report reads from a replica (#198 step 2). The test environment's replica is the test database itself
# (config/database.yml), shared with the writing connection, so the reading role refuses writes as a replica would, and
# config.x.replica_may_be_primary lets that server, which is not in recovery, be read as one.
RSpec.describe ReplicaReads do
  def role_inside = described_class.around { ApplicationRecord.current_role }

  # A stand-in for the replica's pool: tests share the writing pool with the reading role.
  let(:replica_pool) { instance_double(ActiveRecord::ConnectionAdapters::ConnectionPool, role: :reading) }

  def replica_answers(*rows)
    connection = ApplicationRecord.connection
    allow(connection).to receive(:select_rows).and_call_original
    allow(connection).to receive(:select_rows).with(anything, "Replica caught up") { [ rows.size > 1 ? rows.shift : rows.first ] }
  end

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
    expect(statements.last.last).to match(/SELECT pg_is_in_recovery\(\), pg_last_wal_replay_lsn\(\) >= '[0-9A-F]+\/[0-9A-F]+'::pg_lsn/)
  end

  it "reads a standby that has replayed the target" do
    replica_answers([ true, true ])
    expect(role_inside).to eq(:reading)
  end

  describe "a server that is not in recovery (review of #237)" do
    # The real default, from config/application.rb, without a stub (re-review of #237: an unset config.x key is an
    # empty, truthy OrderedOptions, so a stubbed false hid that production read a promoted server).
    it "may be read as a replica in no environment but test" do
      env = { "RAILS_ENV" => "production", "SECRET_KEY_BASE" => "a" * 64, "FLEET_ENCRYPTION_KEY" => "b" * 40,
              "FLEET_DASHBOARD_HOST" => "fleet.example.com", "FLEET_AGENT_HOST" => "agent.example.lan",
              "GOOGLE_CLIENT_ID" => "x", "GOOGLE_CLIENT_SECRET" => "y", "FLEET_RELEASES_DIR" => Dir.mktmpdir,
              "FLEET_BACKUP_STATUS_FILE" => File.join(Dir.mktmpdir, "s"), "BOOTSNAP_CACHE_DIR" => Dir.mktmpdir }
      script = "print [ Rails.configuration.x.replica_may_be_primary, ReplicaReads.primary_allowed? ].inspect"
      out, err, status = Open3.capture3(env, "bin/rails", "runner", script, chdir: Rails.root.to_s, unsetenv_others: false)
      expect(status).to be_success, err
      expect(out.lines.last).to eq("[false, false]")
    end

    it "is allowed only by an exact true, not by an unset (empty) setting" do
      saved = Rails.configuration.x.replica_may_be_primary
      Rails.configuration.x.replica_may_be_primary = ActiveSupport::OrderedOptions.new
      expect(described_class.primary_allowed?).to be(false)
    ensure
      Rails.configuration.x.replica_may_be_primary = saved
    end

    around do |example|
      saved = Rails.configuration.x.replica_may_be_primary
      Rails.configuration.x.replica_may_be_primary = false # as config/application.rb sets it
      example.run
    ensure
      Rails.configuration.x.replica_may_be_primary = saved
    end

    it "is never read as a replica outside the test setup: it is skipped, logged, and the page reads the primary" do
      replica_answers([ false, nil ])
      allow(Rails.logger).to receive(:error).and_call_original
      expect(role_inside).to eq(:writing)
      expect(described_class.down?).to be(true)
      expect(Rails.logger).to have_received(:error)
        .with("[replica] the replica server is not in recovery (promoted, or not a replica); pages read the primary for 30 seconds")
    end
  end

  describe "a replica that lags" do
    before { allow(Rails.configuration.x).to receive(:replica_max_wait_ms).and_return(50) }

    it "waits for it, up to FLEET_REPLICA_MAX_WAIT_MS" do
      replica_answers([ true, false ], [ true, false ], [ true, true ])
      expect(role_inside).to eq(:reading)
    end

    it "starts the wait after the first answer, so opening the replica's connection is not counted as lag" do
      answers = [ [ true, false ], [ true, true ] ]
      connection = ApplicationRecord.connection
      allow(connection).to receive(:select_rows).and_call_original
      allow(connection).to receive(:select_rows).with(anything, "Replica caught up") do
        sleep 0.08 if answers.size == 2 # a cold connection: the first answer takes longer than the whole wait
        [ answers.shift ]
      end
      expect(role_inside).to eq(:reading)
    end

    it "reads the primary when it has not caught up in time, logs it, and tries it again on the next page" do
      replica_answers([ true, false ])
      allow(Rails.logger).to receive(:info).and_call_original
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      expect(role_inside).to eq(:writing)
      expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be_between(0.05, 1)
      expect(described_class.down?).to be_falsey
      expect(Rails.logger).to have_received(:info).with("[replica] not caught up within 50 ms; this page reads the primary")
    end
  end

  describe "a replica that fails" do
    it "is skipped for FLEET_REPLICA_SKIP_SECONDS after its check fails, with the error in the log" do
      allow(Rails.configuration.x).to receive(:replica_skip_seconds).and_return(45)
      connection = ApplicationRecord.connection
      allow(connection).to receive(:select_rows).and_call_original
      allow(connection).to receive(:select_rows).with(anything, "Replica caught up").and_raise(ActiveRecord::ConnectionNotEstablished, "connection refused\nmore")
      expect(Rails.logger).to receive(:error).with("[replica] ActiveRecord::ConnectionNotEstablished: connection refused; pages read the primary for 45 seconds")
      expect(role_inside).to eq(:writing)
      expect(described_class.down?).to be(true)
      expect(described_class.caught_up?).to be(false)
      travel(46.seconds) { expect(described_class.down?).to be(false) }
    end

    it "leaves a failure of the primary's own query alone: it goes on, and the replica is not marked down" do
      connection = ApplicationRecord.connection
      allow(connection).to receive(:select_value).and_call_original
      allow(connection).to receive(:select_value).with(anything, "Replica target").and_raise(ActiveRecord::ConnectionFailed)
      expect { role_inside }.to raise_error(ActiveRecord::ConnectionFailed)
      expect(described_class.down?).to be_falsey
    end

    [ ActiveRecord::ConnectionNotEstablished, ActiveRecord::ConnectionFailed, ActiveRecord::SerializationFailure, ActiveRecord::QueryCanceled ].each do |error|
      it "is marked down when it raises #{error.name.demodulize} while a page reads it, and the page runs again on the primary" do
        roles = []
        value = described_class.around do
          roles << ApplicationRecord.current_role
          raise error.new("replica gone", connection_pool: replica_pool) if roles.size == 1

          :from_primary
        end
        expect(value).to eq(:from_primary)
        expect(roles).to eq(%i[reading writing])
        expect(described_class.down?).to be(true)
      end
    end

    it "finds the replica's error under a view's error" do
      wrapped = begin
        begin
          raise ActiveRecord::ConnectionFailed.new("replica gone", connection_pool: replica_pool)
        rescue ActiveRecord::ConnectionFailed
          raise ActionView::Template::Error, "rendering failed"
        end
      rescue ActionView::Template::Error => e
        e
      end
      calls = 0
      expect(described_class.around { (calls += 1) == 1 ? raise(wrapped) : :again }).to eq(:again)
      expect(described_class.down?).to be(true)
    end

    it "passes the error on, after marking the replica down, when the page cannot run again" do
      expect { described_class.around(fallback: -> { false }) { raise ActiveRecord::ConnectionFailed.new("gone", connection_pool: replica_pool) } }
        .to raise_error(ActiveRecord::ConnectionFailed)
      expect(described_class.down?).to be(true)
    end

    it "is not marked down for another database's error, or for a view error with none of its errors under it" do
      expect { described_class.around { raise ActiveRecord::ConnectionNotEstablished.new("queue gone", connection_pool: SolidQueue::Record.connection_pool) } }
        .to raise_error(ActiveRecord::ConnectionNotEstablished)
      view_error = -> { raise "a broken view" rescue raise ActionView::Template::Error, "rendering failed" } # rubocop:disable Style/RescueModifier
      expect { described_class.around(&view_error) }.to raise_error(ActionView::Template::Error)
      expect(described_class.down?).to be_falsey
    end
  end

  # The GET and HEAD guard (review of #237): a page wrapped with reads_from_replica never reads the replica on another
  # method, whatever the routes say.
  describe ReplicaReads::Controller do
    def role_for(method)
      controller = HostsController.new
      controller.set_request!(ActionDispatch::TestRequest.create("REQUEST_METHOD" => method))
      controller.send(:read_from_replica) { ApplicationRecord.current_role }
    end

    it "reads the replica on GET and HEAD only" do
      expect(role_for("GET")).to eq(:reading)
      expect(role_for("HEAD")).to eq(:reading)
      %w[POST PATCH PUT DELETE].each { |method| expect(role_for(method)).to eq(:writing), method }
    end
  end
end
