require "rails_helper"

# The triage run's claim protocol with real commits (VT-BUCKETS #259, reviews of #269): prepare! releases the changes
# it claimed only after its recomputation committed, outside any transaction; a change recorded meanwhile stays for the
# next run, and a run that fails before releasing leaves every change pending.
RSpec.describe EvaluationRun::Triage do
  self.use_transactional_tests = false

  after do
    TriageRunClaim.delete_all
    TriageRunChunk.delete_all
    EvaluationRun.delete_all
    TriageSignalChange.delete_all
  end

  def run(reason) = EvaluationRun.create!(kind: "triage", scope: { "reason" => reason })

  it "releases what it claimed once its work committed, and keeps a change recorded meanwhile" do
    TriageSignalChange.record!(:kev, cve_ids: %w[CVE-2026-0001])
    TriageSignalChange.record!(:epss, cve_ids: %w[CVE-2026-0002])
    record = run("kev")
    recorded = false
    allow(Advisory).to receive(:where).and_wrap_original do |original, *args, **kwargs|
      TriageSignalChange.record!(:kev, cve_ids: %w[CVE-2026-0001]) unless recorded # re-recorded while the run works: a new id
      recorded = true
      original.call(*args, **kwargs)
    end
    scope = described_class.new(record.scope, record.id).prepare!
    expect(scope).to include("prepared" => true, "full" => false, "chunk_runs" => [ record.id ], "changes" => 1)
    expect(TriageSignalChange.order(:kind).pluck(:kind, :cve_id)).to eq([ %w[epss CVE-2026-0002], %w[kev CVE-2026-0001] ])

    # The daily run claims both.
    daily = run("daily")
    expect(described_class.new(daily.scope, daily.id).prepare!).to include("changes" => 2)
    expect(TriageRunClaim.count).to eq(0) # released, and gone with it
    expect(TriageSignalChange.count).to eq(0)
  end

  # #312: claim had no keyset, so a run claimed its first page again and stopped there, and 2,500 changes took 3 runs.
  it "claims every change pending as it starts, a page at a time by keyset, and leaves a change recorded between pages for the next run" do
    cves = Array.new(2_500) { |i| format("CVE-2026-%05d", i + 1) }
    late = TriageSignalChange.connection.select_value("SELECT #{TriageSignalChange::NEXT_ID}") # an import's id, taken before it commits
    TriageSignalChange.record!(:tracker, cve_ids: cves)
    upto = TriageSignalChange.maximum(:id)
    record = run("daily")
    pages = []
    allow(TriageSignalChange).to receive(:claim).and_wrap_original do |original, **options|
      original.call(**options).tap do |page|
        pages << [ options[:after], page.size, page.last&.id ]
        if pages.size == 1
          TriageSignalChange.record!(:epss, cve_ids: %w[CVE-2026-99999]) # recorded once the claim started
          TriageSignalChange.create!(id: late, kind: "kev", cve_id: "CVE-2026-88888", created_at: Time.current) # committed below the cursor
        end
      end
    end
    scope = described_class.new(record.scope, record.id).prepare!(EvaluationRun::Checkpoint.for(record, described_class::STEPS))
    expect(pages.map { |page| page[1] }).to eq([ 1_000, 1_000, 500 ])
    expect(pages.map(&:first)).to eq([ nil, pages[0][2], pages[1][2] ]) # each page after the last one's last id
    expect(scope).to include("prepared" => true, "full" => false, "changes" => 2_500, "claim_upto" => upto)
    expect(TriageSignalChange.order(:kind).pluck(:kind, :cve_id)).to eq([ %w[epss CVE-2026-99999], %w[kev CVE-2026-88888] ]) # every tracker change released in one run; the others wait
    expect(TriageRunClaim.count).to eq(0)

    following = run("daily") # the next run claims both, the late row included, and releases them (review of #316)
    expect(described_class.new(following.scope, following.id).prepare!).to include("changes" => 2)
    expect(TriageSignalChange.count).to eq(0)
  end

  it "becomes full when a later page claims a kev_all change, and stores that with the page" do
    stub_const("#{described_class}::CLAIM", 2)
    TriageSignalChange.record!(:kev, cve_ids: %w[CVE-2026-0001 CVE-2026-0002 CVE-2026-0003])
    TriageSignalChange.record!(:kev_all)
    record = run("kev")
    allow(VulnerabilityMatcher::Chunks).to receive(:signals_barrier!).and_raise(SignalException, "TERM") # killed after the claim
    expect { described_class.new(record.scope, record.id).prepare!(EvaluationRun::Checkpoint.for(record, described_class::STEPS)) }.to raise_error(SignalException)
    expect(record.reload).to have_attributes(prepare_step: "refresh", scope: include("full" => true, "claim_upto" => TriageSignalChange.maximum(:id)))
    expect(TriageRunClaim.where(evaluation_run_id: record.id).count).to eq(4)
  end

  it "releases nothing when its work fails, keeping its claims in their table, and releases them once resumed prepared" do
    TriageSignalChange.record!(:kev_all)
    record = run("kev")
    allow(VulnerabilityMatcher::Chunks).to receive(:signals_barrier!).and_raise(ActiveRecord::Deadlocked)
    expect { described_class.new(record.scope, record.id).prepare!(EvaluationRun::Checkpoint.for(record, described_class::STEPS)) }.to raise_error(ActiveRecord::Deadlocked)
    expect(TriageSignalChange.pluck(:kind)).to eq([ "kev_all" ])
    expect(TriageRunClaim.where(evaluation_run_id: record.id).count).to eq(1)
    expect(record.reload).to have_attributes(prepare_step: "refresh", scope: { "reason" => "kev", "chunk_runs" => [ record.id ], "full" => true, "claim_upto" => TriageSignalChange.maximum(:id) }) # nothing big in it

    prepared = record.scope.merge("prepared" => true) # as a run killed between storing its prepared scope and its release
    expect(described_class.new(prepared, record.id).prepare!).to eq(prepared)
    expect(TriageSignalChange.count).to eq(0)
    expect(TriageRunClaim.count).to eq(0)
    expect(described_class.new(prepared, record.id).prepare!).to eq(prepared) # nothing left to release
  end

  # Review of #308, nit 1: a kill between the claim's commit and the barrier must not skip the barrier for good, or a
  # resume could read which chunks hold the advisories before a match that read the old signals has committed (B3).
  it "waits at the signals barrier again on a resume after a kill between its claim and the barrier" do
    TriageSignalChange.record!(:kev, cve_ids: %w[CVE-2026-0001])
    record = run("kev")
    allow(VulnerabilityMatcher::Chunks).to receive(:signals_barrier!).and_raise(SignalException, "TERM")
    expect { described_class.new(record.scope, record.id).prepare!(EvaluationRun::Checkpoint.for(record, described_class::STEPS)) }.to raise_error(SignalException)
    expect(record.reload.prepare_step).to eq("refresh") # its claim committed
    allow(VulnerabilityMatcher::Chunks).to receive(:signals_barrier!).and_call_original

    session = separate_session
    session.begin_db_transaction
    session.execute("SELECT pg_advisory_xact_lock_shared(#{VulnerabilityMatcher::Chunks::SIGNALS_LOCK.join(', ')})") # a match in flight
    order = Queue.new
    allow(ChunkMatch).to receive(:where).and_wrap_original do |original, *args, **kwargs|
      order << :chunks_read
      original.call(*args, **kwargs)
    end
    runner = Thread.new do
      ApplicationRecord.connection_pool.with_connection { described_class.new(record.scope, record.id).prepare!(EvaluationRun::Checkpoint.for(record, described_class::STEPS)) }
    end
    sleep 0.5
    expect(runner).to be_alive # the resume waits at the barrier
    order << :match_committed
    session.commit_db_transaction
    runner.join(10)
    expect(runner.value).to include("prepared" => true)
    expect(Array.new(order.size) { order.pop }.first(2)).to eq(%i[match_committed chunks_read])
  ensure
    session&.disconnect!
  end

  # Review of #277, B3: a match that read the signals before a KEV import committed must have committed before the run
  # reads which chunks hold the advisory, or its new chunk keeps its pre-KEV base. The match holds the signals lock
  # shared from before it reads them until it commits; the run's barrier waits for it.
  it "waits, before it reads which chunks hold the advisories, for every match that read the signals before they changed" do
    session = separate_session
    session.begin_db_transaction
    session.execute("SELECT pg_advisory_xact_lock_shared(#{VulnerabilityMatcher::Chunks::SIGNALS_LOCK.join(', ')})") # a match in flight
    TriageSignalChange.record!(:kev, cve_ids: %w[CVE-2026-0001])
    record = run("kev")
    order = Queue.new
    allow(ChunkMatch).to receive(:where).and_wrap_original do |original, *args, **kwargs|
      order << :chunks_read
      original.call(*args, **kwargs)
    end
    runner = Thread.new { ApplicationRecord.connection_pool.with_connection { described_class.new(record.scope, record.id).prepare! } }
    sleep 0.5
    expect(runner).to be_alive # waiting at the barrier
    order << :match_committed
    session.commit_db_transaction
    runner.join(10)
    expect(runner.value).to include("prepared" => true)
    expect(Array.new(order.size) { order.pop }.first(2)).to eq(%i[match_committed chunks_read])
  ensure
    session&.disconnect!
  end

  it "refuses the signals barrier inside an open transaction, where its lock would outlast the barrier" do
    ApplicationRecord.transaction do
      expect { VulnerabilityMatcher::Chunks.signals_barrier! }.to raise_error(ArgumentError, /outside a transaction/)
    end
  end

  # Re-check of #277, S2: a run still preparing may refresh after a covering run read the bases, so nothing covers it
  # (since #295 no run carries another's id: a retry reopens the run itself).
  it "never covers a run that is not prepared, not even for being full or carrying its id" do # M10
    preparing = run("kev").tap { |r| r.update!(scope: r.scope.merge("chunk_runs" => [ r.id ])) }
    full = described_class.new({ "reason" => "all", "prepared" => true, "chunk_runs" => [ 0 ] }, 0)
    expect(full.covers?(preparing.work)).to be(false)
    carrying = described_class.new({ "reason" => "kev", "prepared" => true, "chunk_runs" => [ preparing.id ] }, 0)
    expect(carrying.covers?(preparing.work)).to be(false)
    expect(full.covers?(described_class.new({ "reason" => "kev", "prepared" => true, "chunk_runs" => [ 5 ], "advisory_ids" => [ 1 ] }, 5))).to be(true)
  end
end
