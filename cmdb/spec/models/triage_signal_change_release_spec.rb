require "rails_helper"

# The claim protocol with real commits on two connections (reviews of #269): a change recorded between a claim and its
# release is never lost, and release! never waits on, or deadlocks with, an import re-recording what it claimed.
RSpec.describe TriageSignalChange do
  self.use_transactional_tests = false

  after { described_class.delete_all }

  # An import on a connection of its own: the same upsert record! runs, inside a transaction it controls.
  def import_session = separate_session

  def re_record(session, cve_id)
    session.execute(described_class.sanitize_sql_array([ described_class::INSERT["cve"], "kev", PG::TextEncoder::Array.new.encode([ cve_id ]) ]))
  end

  def pending = described_class.order(:cve_id).pluck(:cve_id, :id)

  it "never loses a change recorded between a claim and its release" do
    described_class.record!(:kev, cve_ids: %w[CVE-2026-0001 CVE-2026-0002])
    described_class.record!(:kev_all)
    claimed = described_class.claim(kinds: %w[kev kev_all], limit: 10)
    expect(claimed.map { |c| c.cve_id || c.kind }).to eq(%w[CVE-2026-0001 CVE-2026-0002 kev_all])
    described_class.record!(:kev, cve_ids: %w[CVE-2026-0001]) # recorded again, and committed, while the run works
    described_class.record!(:kev_all)
    expect(described_class.release!(claimed.map(&:id))).to eq(1)
    expect(described_class.where(kind: "kev").pluck(:cve_id)).to eq(%w[CVE-2026-0001])
    expect(described_class.where(kind: "kev_all").count).to eq(1)
  end

  # The re-check's reproduction: the run releases [A, B] while an import has re-recorded B and then re-records A. Deleting
  # in id order, release! waited on B while holding A, and the import then waited on A: a deadlock, which killed either
  # side. With SKIP LOCKED, release! deletes A, skips B at once, and the import commits both as new rows.
  it "skips rows an import holds, so neither waits and nothing deadlocks" do
    described_class.record!(:kev, cve_ids: %w[CVE-2026-000A CVE-2026-000B])
    claimed = described_class.claim(kinds: %w[kev])
    session = import_session
    session.begin_db_transaction
    re_record(session, "CVE-2026-000B") # the import's DO UPDATE locks B until it commits
    importer = Thread.new do
      sleep 0.5
      re_record(session, "CVE-2026-000A")
      session.commit_db_transaction
      :committed
    rescue StandardError => e
      session.rollback_db_transaction
      e
    end
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    released = described_class.release!(claimed.map(&:id))
    expect(Process.clock_gettime(Process::CLOCK_MONOTONIC) - started).to be < 0.5 # it did not wait for the import
    expect(importer.value).to eq(:committed)
    expect(released).to eq(1) # A; B was skipped
    ids = claimed.map(&:id)
    expect(pending.map(&:first)).to eq(%w[CVE-2026-000A CVE-2026-000B])
    expect(pending.map(&:last)).to all(satisfy { |id| ids.exclude?(id) }) # both are the import's new versions
  ensure
    session&.disconnect!
  end

  it "keeps a skipped row whose import rolled back, for the next run to process again" do
    described_class.record!(:kev, cve_ids: %w[CVE-2026-000C])
    claimed = described_class.claim(kinds: %w[kev])
    session = import_session
    session.begin_db_transaction
    re_record(session, "CVE-2026-000C")
    expect(described_class.release!(claimed.map(&:id))).to eq(0)
    session.rollback_db_transaction
    expect(pending).to eq([ [ "CVE-2026-000C", claimed.first.id ] ]) # the old version, claimed again next time
  ensure
    session&.disconnect!
  end
end
