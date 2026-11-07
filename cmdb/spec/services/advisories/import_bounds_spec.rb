require "rails_helper"

# The bounds an upload's import runs within (review of #129, S1): how long it may wait for the import lock, and
# how long it may read and store once it holds it. The feed and the rake task pass neither.
RSpec.describe Advisories::Import do
  # Another session holding the import lock, as a feed refresh importing would.
  def with_lock_held_elsewhere
    # The same server, database, and credentials as the test's own connection, however they were configured.
    other = PG.connect(ActiveRecord::Base.connection.raw_connection.conninfo_hash.compact.reject { |_, value| value == "" })
    other.exec("SELECT pg_advisory_lock(hashtext(#{other.escape_literal(described_class::LOCK_KEY)}))")
    yield
  ensure
    other&.close
  end

  def reader = Advisories::Reader.new(osv_directory(osv_record(id: "DSA-9001-1")))

  it "gives up waiting for the lock after lock_timeout, writing nothing" do
    with_lock_held_elsewhere do
      expect { described_class.new(origin: "file", source: "a.zip").call(reader, lock_timeout: 1) }.to raise_error(ActiveRecord::LockWaitTimeout)
    end
    expect([ Advisory.count, AdvisoryImport.count ]).to eq([ 0, 0 ])
  end

  it "stops past time_limit as unreadable, rolling back what it stored" do
    expect { described_class.new(origin: "file", source: "a.zip").call(reader, time_limit: 0) }
      .to raise_error(Advisories::Unreadable, "a.zip took longer than 0 minutes to import, so nothing was imported; import it on the server with bin/rails advisories:import")
    expect([ Advisory.count, AdvisoryImport.count ]).to eq([ 0, 0 ])
  end

  # Review of #129: every full import (the feed, the rake task, an upload) counts per ecosystem before the sweep
  # writes, with the thresholds from the configuration (FLEET_ADVISORY_WITHDRAW_SHARE, _MIN_RECORDS).
  describe "the withdrawal guard" do
    before { import_advisories(*(1..5).map { |i| osv_record(id: "DSA-900#{i}-1") }, full: true, origin: "feed") }

    def full_import(origin: "file", **options) = described_class.new(origin:, source: "b.zip", full: true, **options).call(reader)

    %w[feed file].each do |origin|
      it "refuses a full #{origin} import that would withdraw too much, with the counts, writing nothing" do
        expect { full_import(origin:) }.to raise_error(described_class::WithdrawalsRefused) { |error|
          expect(error.withdrawals).to eq("Debian:13" => { "withdraw" => 4, "current" => 5, "records" => 1 })
        }
        expect(Advisory.current.count).to eq(5)
        expect(AdvisoryImport.count).to eq(1)
      end
    end

    it "proceeds when the confirmed counts cover it" do
      expect(full_import(allowed_withdrawals: { "Debian:13" => 4 }).import.counts["absent"]).to eq(4)
    end

    it "refuses when the confirmed counts are fewer than it would withdraw" do
      expect { full_import(allowed_withdrawals: { "Debian:13" => 3 }) }.to raise_error(described_class::WithdrawalsRefused)
    end

    it "uses the configured share and record floor", withdrawal_guard: { share: 0.9, min_records: 1 } do
      expect(full_import.import.counts["absent"]).to eq(4)
    end

    it "applies the same rule to any ecosystem, not only the fleet's current one" do
      stub_const("Ecosystems::TABLE", Ecosystems::TABLE.merge([ "example", "1" ] => "Example:1"))
      import_advisories(*(1..3).map { |i| osv_record(id: "EX-#{i}", ecosystem: "Example:1") }, full: true)
      only_one = Advisories::Reader.new(osv_directory(osv_record(id: "EX-1", ecosystem: "Example:1")))
      expect { described_class.new(origin: "feed", source: "x.zip", full: true).call(only_one) }.to raise_error(described_class::WithdrawalsRefused) { |error|
        expect(error.withdrawals).to eq("Example:1" => { "withdraw" => 2, "current" => 3, "records" => 1 })
      }
    end

    it "reads its thresholds from the environment, refusing a value it cannot use" do
      initializer = Rails.root.join("config/initializers/advisories.rb").read
      expect(initializer).to include('ENV["FLEET_ADVISORY_WITHDRAW_SHARE"].presence || "0.10"', 'ENV["FLEET_ADVISORY_WITHDRAW_MIN_RECORDS"].presence || "1000"')
      expect(Advisories.config).to have_attributes(withdraw_share: 0.10, withdraw_min_records: 1000)
    end
  end
end
