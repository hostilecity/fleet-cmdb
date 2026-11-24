require "rails_helper"

# A run's preparation checkpoint (#295): steps done are skipped, a paged step carries on after its cursor, and each
# write is a compare-and-set on the run's row, so two preparations of one run cannot both go on. The kill-point specs
# are in spec/jobs/evaluation_run_watch_job_spec.rb (advisory runs) and spec/services/vulnerability_triage_matching_spec.rb
# (triage runs).
RSpec.describe EvaluationRun::Checkpoint do
  include ActiveJob::TestHelper

  let(:steps) { %w[first paged last] }

  def run(**attributes) = EvaluationRun.create!(kind: "advisories", scope: { "packages" => { "Debian:13" => [ "curl" ] } }, **attributes)

  describe "detached (in memory)" do
    it "runs each step once, in order, carries a paged step on after its cursor, and stores a step's scope with its move" do
      checkpoint = described_class.detached(steps)
      seen = []
      checkpoint.step!("first") { seen << :first }
      checkpoint.pages!("paged", [ 1, 3, 5 ], 2) { |slice| seen << slice }
      expect(checkpoint).to have_attributes(step: "last", cursor: nil, writes: 4) # the first step, a write a page, the move on
      checkpoint.step!("last") { seen << :last }
      expect(seen).to eq([ :first, [ 1, 3 ], [ 5 ], :last ])
      expect(checkpoint.step).to eq(described_class::PREPARED)
      checkpoint.step!("first") { raise "done already" }

      resumed = described_class.new(nil, steps, "paged", 3)
      expect(resumed.done?("first")).to be(true)
      expect(resumed.done?("paged")).to be(false)
      expect([ resumed.after("paged"), resumed.after("last") ]).to eq([ 3, nil ]) # what the step reads after, in SQL
      slices = []
      resumed.pages!("paged", [ 1, 3, 5, 7 ], 10) { |slice| slices << slice }
      expect(slices).to eq([ [ 5, 7 ] ])
      past = described_class.new(nil, steps, "paged", 9)
      past.pages!("paged", [ 1, 3 ], 10) { raise "nothing is left" }
      expect(past.step).to eq("last")
    end

    it "works through a keyset step a page at a time, carrying on after its cursor, and moves on after a short page (#312)" do
      checkpoint = described_class.detached(steps)
      checkpoint.step!("first") { nil }
      seen = []
      checkpoint.keyset!("paged", EvaluationRun) do |after|
        seen << after
        { nil => [ 2, true, nil ], 2 => [ 4, true, nil ], 4 => [ 5, false, nil ] }.fetch(after)
      end
      expect(seen).to eq([ nil, 2, 4 ])
      expect(checkpoint).to have_attributes(step: "last", cursor: nil, writes: 4)
      checkpoint.keyset!("paged", EvaluationRun) { raise "done already" }

      resumed = described_class.new(nil, steps, "paged", 4)
      afters = []
      resumed.keyset!("paged", EvaluationRun) { |after| (afters << after) && [ nil, true, nil ] } # an empty page ends it
      expect(afters).to eq([ 4 ])
      expect(resumed.step).to eq("last")
      stuck = described_class.new(nil, steps, "paged", 4)
      expect { stuck.keyset!("paged", EvaluationRun) { [ 4, true, nil ] } }.to raise_error(ArgumentError, /must end after 4/) # a page read again
    end

    it "prepares from the start when the stored step is not one of the kind's (the code changed between attempts)" do
      checkpoint = described_class.new(nil, steps, "gone", 42)
      expect(checkpoint.done?("first")).to be(false)
      ran = []
      checkpoint.pages!("paged", [ 1 ], 10) { |slice| ran << slice } # its cursor belonged to another step
      expect(ran).to eq([ [ 1 ] ])
    end

    it "prepares from the start when it was written under another step list, as when a step was added before it (review of #308)" do
      before = described_class.plan(%w[paged last])
      checkpoint = described_class.new(nil, steps, "last", nil, before) # "first" was added since "last" was reached
      expect(checkpoint.done?("first")).to be(false)
      expect(checkpoint.after("last")).to be_nil
      expect(described_class.new(nil, steps, "last", nil, described_class.plan(steps)).done?("first")).to be(true)
    end
  end

  describe "on a run" do
    it "moves only from where it last left the run, and only while it is queued" do
      record = run
      mine = described_class.for(record, steps)
      mine.step!("first") { { "packages" => {}, "note" => 7 } }
      expect(record.reload).to have_attributes(prepare_step: "paged", prepare_cursor: nil, prepare_plan: described_class.plan(steps), scope: { "packages" => {}, "note" => 7 })
      replanned = described_class.for(record, %w[other paged last]) # the steps changed: it starts again, from what is stored
      replanned.advance!("other")
      expect(record.reload).to have_attributes(prepare_step: "other", prepare_plan: described_class.plan(%w[other paged last]))
      record.update_columns(prepare_step: "paged", prepare_plan: described_class.plan(steps))
      mine = described_class.for(record, steps)

      other = described_class.for(record, steps) # a second preparation of the same run (a resume of one thought dead)
      other.advance!("paged", 10)
      expect { mine.advance!("paged", 4) }.to raise_error(described_class::Lost)
      expect(record.reload).to have_attributes(prepare_step: "paged", prepare_cursor: 10)

      record.update_columns(state: "superseded")
      expect { other.advance!("last") }.to raise_error(described_class::Lost, /no longer queued/)
    end

    it "commits a keyset page's work with its cursor, and rolls the page back when another preparation moved it (#312)" do
      record = run
      mine = described_class.for(record, steps)
      mine.step!("first") { nil }
      mine.keyset!("paged", EvaluationRun) do |after|
        record.update_columns(scope: { "page" => after.to_i + 1 }) # the page's work
        [ after.to_i + 1, after.nil?, ({ "page" => 1, "stored" => true } if after.nil?) ]
      end
      expect(record.reload).to have_attributes(prepare_step: "last", scope: { "page" => 2 }) # two pages, the first's scope stored with it

      record.update_columns(prepare_step: "paged", prepare_cursor: 1)
      mine = described_class.for(record.reload, steps)
      described_class.for(record, steps).advance!("paged", 99) # a second preparation of the run moved it meanwhile
      expect do
        mine.keyset!("paged", EvaluationRun) { |after| record.update_columns(scope: { "page" => "lost" }) && [ after + 1, true, nil ] }
      end.to raise_error(described_class::Lost)
      expect(record.reload).to have_attributes(prepare_step: "paged", prepare_cursor: 99, scope: { "page" => 2 }) # the page rolled back with it
    end

    it "touches the run, so the watch never takes a preparation that is moving for dead" do
      record = run
      record.update_columns(updated_at: 1.hour.ago)
      described_class.for(record, steps).advance!("paged", 1)
      expect(record.reload.updated_at).to be > 1.minute.ago
    end
  end

  describe "two fan-outs of one run" do
    let!(:hosts) do
      perform_enqueued_jobs do
        import_advisories(osv_record(id: "DSA-0-1", package: "vim", fixed: "2:9.1-2"))
        [ debian_host(packages: [ [ "curl", "8.14.1-1", "curl" ] ]), debian_host(packages: [ [ "curl", "8.14.1-1", "curl" ], [ "vim", "2:9.1-1", "vim" ] ]) ]
      end
    end

    before do
      stub_const("EvaluationRun::BATCH_SIZE", 1)
      stub_const("EvaluationRun::Advisories::MATCH_PAGE", 1)
      import_advisories(osv_record(id: "DSA-1-1", package: "curl", fixed: "8.14.1-2"))
      clear_enqueued_jobs
    end

    let(:record) { EvaluationRun.where(kind: "advisories").order(:id).last }

    it "stops the one whose checkpoint write misses, quietly, and leaves the run to the other" do
      allow(VulnerabilityMatcher::Chunks).to receive(:restamp!).and_wrap_original do |original, *args|
        record.update_columns(prepare_cursor: -1) # another preparation moved it meanwhile
        original.call(*args)
      end
      allow(Rails.logger).to receive(:warn)
      expect(record.fan_out!).to be_nil
      expect(Rails.logger).to have_received(:warn).with(/its preparation moved on elsewhere.*this preparation stops/)
      expect(record.reload).to have_attributes(state: "queued", batch_count: 0)
      expect(record.batches).to be_empty
      expect(enqueued_jobs).to be_empty
    end

    it "queues only the batches with no live job when it finds the run split by the other" do
      rules = EvaluationRun.create!(kind: "cis_rules", scope: { "rule_ids" => [ 0 ] }) # nothing to prepare, so both reach the split
      first = EvaluationRun.find(rules.id)
      second = EvaluationRun.find(rules.id) # read while the run was queued
      first.fan_out!
      batches = first.batches.order(:position).pluck(:id)
      clear_enqueued_jobs
      SolidQueue::Job.create!(queue_name: "evaluation", class_name: "EvaluationBatchJob", arguments: { "arguments" => [ batches.first ] }) # the first's, still queued
      second.fan_out!
      expect(enqueued_jobs.map { |job| job["arguments"] }).to eq([ [ batches.second ] ])
      expect(rules.reload).to have_attributes(state: "running", batch_count: 2)
    end
  end
end
