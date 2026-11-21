require "rails_helper"

# The triage run's claim protocol with real commits (VT-BUCKETS #259, reviews of #269): prepare! releases the changes
# it claimed only after its recomputation committed, outside any transaction; a change recorded meanwhile stays for the
# next run, and a run that fails before releasing leaves every change pending.
RSpec.describe EvaluationRun::Triage do
  self.use_transactional_tests = false

  after do
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
    expect(described_class.new(run("daily").scope, 0).prepare!).to include("changes" => 2)
    expect(TriageSignalChange.count).to eq(0)
  end

  it "releases nothing when its work fails, and returns a prepared scope unchanged" do
    TriageSignalChange.record!(:kev_all)
    record = run("kev")
    allow(VulnerabilityTriage::Base).to receive(:refresh!).and_raise(ActiveRecord::Deadlocked)
    allow(ChunkEvaluation).to receive(:distinct).and_return(instance_double(ActiveRecord::Relation, pluck: [ 1 ]))
    expect { described_class.new(record.scope, record.id).prepare! }.to raise_error(ActiveRecord::Deadlocked)
    expect(TriageSignalChange.pluck(:kind)).to eq([ "kev_all" ])

    prepared = { "reason" => "kev", "prepared" => true, "chunk_runs" => [ 7 ] }
    expect(described_class.new(prepared, record.id).prepare!).to eq(prepared)
  end
end
