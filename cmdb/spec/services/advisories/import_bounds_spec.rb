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

  # Review of #129 (S2), at the importer: the guard counts per ecosystem before the sweep writes.
  describe "guard_withdrawals" do
    before { import_advisories(*(1..5).map { |i| osv_record(id: "DSA-900#{i}-1") }, full: true) }

    def full_import(**options) = described_class.new(origin: "file", source: "b.zip", full: true, **options).call(reader)

    it "refuses a full import that would withdraw too much, with the counts, writing nothing" do
      expect { full_import(guard_withdrawals: true) }.to raise_error(described_class::WithdrawalsRefused) { |error|
        expect(error.withdrawals).to eq("Debian:13" => { "withdraw" => 4, "current" => 5, "records" => 1 })
      }
      expect(Advisory.current.count).to eq(5)
      expect(AdvisoryImport.count).to eq(1)
    end

    it "proceeds when the confirmed counts cover it, and is not applied to the feed or the rake task" do
      expect(full_import(guard_withdrawals: true, allowed_withdrawals: { "Debian:13" => 4 }).import.counts["absent"]).to eq(4)
      import_advisories(*(2..5).map { |i| osv_record(id: "DSA-900#{i}-1") }, full: false) # restored as current
      expect(full_import.import.counts["absent"]).to eq(4)
    end

    it "allows a small share of a large set of records" do
      stub_const("#{described_class}::SMALL_FILE_RECORDS", 1)
      stub_const("#{described_class}::WITHDRAW_SHARE", 0.9)
      expect(full_import(guard_withdrawals: true).import.counts["absent"]).to eq(4)
    end
  end
end
