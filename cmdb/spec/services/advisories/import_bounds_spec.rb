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

  # Review of #131.
  describe "the withdrawal guard's share and allowance" do
    def records(ids) = Advisories::Reader.new(osv_directory(*ids.map { |id| osv_record(id:) }))

    def full_import(ids, **options) = described_class.new(origin: "feed", source: "x.zip", full: true, **options).call(records(ids))

    before { import_advisories(*(1..10).map { |i| osv_record(id: "DSA-#{i}-1") }, full: true, origin: "feed") }

    it "takes the share of the ecosystem's advisories before the import, so advisories it adds cannot dilute it",
       withdrawal_guard: { share: 0.1, min_records: 0 } do
      kept_and_added = (1..8).map { |i| "DSA-#{i}-1" } + (11..20).map { |i| "DSA-#{i}-1" } # withdraws 2 of 10 (20%), not 2 of 20
      expect { full_import(kept_and_added) }.to raise_error(described_class::WithdrawalsRefused) { |error|
        expect(error.withdrawals).to eq("Debian:13" => { "withdraw" => 2, "current" => 10, "records" => 18 })
      }
      expect(Advisory.current.count).to eq(10)
    end

    it "treats an allowance as a ceiling, whatever the thresholds would allow", withdrawal_guard: { share: 0.9, min_records: 0 } do
      expect { full_import((1..8).map { |i| "DSA-#{i}-1" }, allowed_withdrawals: { "Debian:13" => 1 }) }.to raise_error(described_class::WithdrawalsRefused)
      expect(Advisory.current.count).to eq(10)
      expect(full_import((1..8).map { |i| "DSA-#{i}-1" }, allowed_withdrawals: { "Debian:13" => 2 }).import.counts["absent"]).to eq(2)
    end

    it "allows no withdrawals for an ecosystem an allowance does not name", withdrawal_guard: { share: 0.9, min_records: 0 } do
      expect { full_import((1..9).map { |i| "DSA-#{i}-1" }, allowed_withdrawals: { "Other:1" => 5 }) }.to raise_error(described_class::WithdrawalsRefused)
    end

    it "holds a confirmed re-download to the count even when it crosses the record floor", withdrawal_guard: { share: 0.5, min_records: 9 } do
      # The first download had 8 records (under the floor) and withdrew 2; the operator confirmed 2. The re-download
      # has 9 records, over the floor, and would withdraw 3 (30%, under the share): the confirmed 2 still caps it.
      import_advisories(osv_record(id: "DSA-11-1"), full: false)
      expect { full_import((1..8).map { |i| "DSA-#{i}-1" } + [ "DSA-12-1" ], allowed_withdrawals: { "Debian:13" => 2 }) }
        .to raise_error(described_class::WithdrawalsRefused) { |error| expect(error.withdrawals.dig("Debian:13", "withdraw")).to eq(3) }
    end
  end

  it "records a held-back import with its own state and audit action, not as a failure" do
    refusal = described_class::WithdrawalsRefused.new("Debian:13" => { "withdraw" => 4, "current" => 5, "records" => 1 })
    import = described_class.record_held_back(refusal, origin: "feed", source: "x.zip", full: true)
    expect(import).to have_attributes(state: "held_back", reason: refusal.message, counts: { "would_withdraw" => refusal.withdrawals })
    expect(AuditEntry.sole).to have_attributes(action: "advisory.import_held_back", actor_type: "system")
    expect(AuditEntry.sole.changeset["would_withdraw"]).to eq(refusal.withdrawals)
  end
end
