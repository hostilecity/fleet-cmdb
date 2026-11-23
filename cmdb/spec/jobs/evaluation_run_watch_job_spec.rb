require "rails_helper"

# #278: an advisory re-match, a matching re-match (#270), or a rule run whose worker is killed (a deploy's restart past
# the shutdown timeout, the OOM killer). Solid Queue fails the job without a retry and after_discard never runs, so
# EvaluationRunWatchJob resumes the run from what it recorded, and fails it with a reason after
# EvaluationRun::RESUMES resumes with no progress. Each spec kills the worker at one point and checks that both hosts
# end up as one job matching (or evaluating) the whole fleet leaves them. The triage runs' own cases are in
# spec/services/vulnerability_triage_matching_spec.rb.
RSpec.describe EvaluationRunWatchJob do
  include ActiveJob::TestHelper

  before { stub_const("EvaluationRun::BATCH_SIZE", 1) } # a batch a host

  # A job as Solid Queue leaves a killed worker's: failed, with no retry (ProcessExitError).
  def killed_job(class_name, argument)
    job = SolidQueue::Job.create!(queue_name: "evaluation", class_name:, arguments: { "arguments" => [ argument ] })
    SolidQueue::FailedExecution.create!(job:, error: { "exception_class" => "SolidQueue::Processes::ProcessExitError", "message" => "killed", "backtrace" => [] })
  end

  def live_job(class_name, argument) = SolidQueue::Job.create!(queue_name: "evaluation", class_name:, arguments: { "arguments" => [ argument ] })

  def watch(after: 11.minutes) = travel(after) { described_class.perform_now }

  def outcome(resumed: [], failed: [], finished: []) = { "resumed" => resumed, "failed" => failed, "finished" => finished }

  def batch_jobs = enqueued_jobs.select { |job| job["job_class"] == "EvaluationBatchJob" }

  # Runs the first queued batch job, and forgets the rest (the worker was killed before them).
  def one_batch_then_killed
    job = batch_jobs.first
    clear_enqueued_jobs
    EvaluationBatchJob.perform_now(*ActiveJob::Arguments.deserialize(job["arguments"]))
  end

  # The run's worker is killed by raising SignalException where Solid Queue would stop it, with nothing retried.
  def killed!(&) = expect(&).to raise_error(SignalException)

  describe "an advisory re-match" do
    let!(:hosts) do
      perform_enqueued_jobs do
        import_advisories(osv_record(id: "DSA-0-1", package: "vim", fixed: "2:9.1-2")) # data for Debian 13
        [ debian_host(packages: [ [ "curl", "8.14.1-1", "curl" ] ]), debian_host(packages: [ [ "libcurl4", "8.14.1-1", "curl" ], [ "vim", "2:9.1-1", "vim" ] ]) ]
      end
    end

    before { clear_enqueued_jobs }

    def findings = VulnerabilityFinding.with_details.order(:host_id, :advisory_id, :package).pluck(:host_id, :advisory_id, :package, :state, :resolution, :fixed_version)

    def evaluations = HostVulnerabilityEvaluation.order(:host_id).pluck(:host_id, :state, :reason)

    # The import's run, not started yet: its fan-out job is queued, and nothing has run.
    def import_curl
      import_advisories(osv_record(id: "DSA-1-1", package: "curl", fixed: "8.14.1-2"))
      run = EvaluationRun.where(kind: "advisories").order(:id).last
      expect(run).to have_attributes(state: "queued", scope: include("packages" => { "Debian:13" => [ "curl" ] }))
      run
    end

    # Both hosts as one job matching the whole fleet against the newest data leaves them, with curl's finding open.
    def expect_both_hosts_correct
      expect(VulnerabilityFinding.where(host: hosts.first).active.pluck(:package)).to eq([ "curl" ])
      expect(VulnerabilityFinding.where(host: hosts.second).active.pluck(:package)).to contain_exactly("libcurl4", "vim")
      expect { VulnerabilityMatcher.match_again! }.not_to(change { [ findings, evaluations ] })
    end

    it "resumes a run killed while it was being prepared, part way through matching its chunks, from its checkpoint" do
      run = import_curl
      stub_const("VulnerabilityMatcher::Chunks::BATCH", 1)
      calls = 0
      allow(VulnerabilityMatcher::Chunks).to receive(:match_slice).and_wrap_original do |original, *args|
        calls += 1
        raise SignalException, "TERM" if calls == 2 # the first chunk is matched and committed

        original.call(*args)
      end
      clear_enqueued_jobs
      killed! { run.fan_out! }
      killed_job("EvaluationRunJob", run.id)
      RSpec::Mocks.space.proxy_for(VulnerabilityMatcher::Chunks).reset
      expect(described_class.perform_now).to eq(outcome) # untouched for less than 10 minutes: left alone
      expect(watch).to eq(outcome(resumed: [ run.id ]))
      expect(run.reload).to have_attributes(state: "queued", scope: include("resumes" => 1, "resume_progress" => [ "queued", 0, "match:Debian:13", nil ]))
      perform_evaluation_jobs
      expect(run.reload).to have_attributes(state: "finished", batches_done: 2, host_count: 2, hosts_done: 2)
      expect_both_hosts_correct
    end

    it "resumes a run killed after it was split, before its batch jobs were queued" do
      run = import_curl
      clear_enqueued_jobs
      allow(ActiveJob).to receive(:perform_all_later).and_raise(SignalException, "TERM")
      killed! { run.fan_out! }
      expect(run.reload).to have_attributes(state: "running", batch_count: 2)
      RSpec::Mocks.space.proxy_for(ActiveJob).reset
      killed_job("EvaluationRunJob", run.id)
      expect(watch).to eq(outcome(resumed: [ run.id ]))
      perform_enqueued_jobs(only: EvaluationRunJob)
      expect(batch_jobs.map { |job| job["arguments"].first }).to match_array(run.batches.pluck(:id)) # its batches, not a new split
      perform_evaluation_jobs
      expect(run.reload).to have_attributes(state: "finished", batches_done: 2, hosts_done: 2)
      expect_both_hosts_correct
    end

    it "resumes a run killed between its batches from the batch it had left" do
      run = import_curl
      perform_enqueued_jobs(only: EvaluationRunJob)
      one_batch_then_killed
      left = run.batches.pluck(:id)
      expect(left.size).to eq(1)
      killed_job("EvaluationBatchJob", left.first)
      expect(watch).to eq(outcome(resumed: [ run.id ]))
      expect(run.reload.scope).to include("resumes" => 1, "resume_progress" => [ "running", 1, "prepared", nil ])
      perform_enqueued_jobs(only: EvaluationRunJob)
      expect(batch_jobs.map { |job| job["arguments"] }).to eq([ left ])
      perform_evaluation_jobs
      expect(run.reload).to have_attributes(state: "finished", batches_done: 2, hosts_done: 2)
      expect_both_hosts_correct
    end

    it "resumes a run whose batch was killed after its hosts were matched, before it was counted, and counts it once" do
      run = import_curl
      perform_enqueued_jobs(only: EvaluationRunJob)
      calls = 0
      allow(EvaluationRun).to receive(:batch_done!).and_wrap_original do |original, *args|
        calls += 1
        raise SignalException, "KILL" if calls == 1 # its hosts' transitions have committed

        original.call(*args)
      end
      job = batch_jobs.first
      clear_enqueued_jobs
      batch_id = job["arguments"].first
      killed! { EvaluationBatchJob.new(batch_id).perform(batch_id) } # perform alone: a killed worker runs no callback
      killed_job("EvaluationBatchJob", batch_id)
      expect(run.reload).to have_attributes(state: "running", batches_done: 0)
      expect(watch).to eq(outcome(resumed: [ run.id ]))
      perform_evaluation_jobs
      expect(run.reload).to have_attributes(state: "finished", batches_done: 2, hosts_done: 2)
      expect_both_hosts_correct
    end

    it "finishes, rather than resumes, a run killed after it was split into no batch" do
      import_advisories(osv_record(id: "DSA-2-1", package: "zsh", fixed: "5.9-9")) # no host has zsh
      run = EvaluationRun.where(kind: "advisories").order(:id).last
      clear_enqueued_jobs
      allow(run).to receive(:finish_empty!).and_raise(SignalException, "TERM")
      killed! { run.fan_out! }
      expect(run.reload).to have_attributes(state: "running", batch_count: 0)
      expect(watch).to eq(outcome(finished: [ run.id ]))
      expect(run.reload.state).to eq("finished")
      expect(evaluation_runs).to be_empty # nothing queued again
    end

    it "resumes a run again when the watch was killed after its resume committed, before the job was queued" do
      run = import_curl
      clear_enqueued_jobs # the worker was killed before the fan-out ran
      expect(watch).to eq(outcome(resumed: [ run.id ]))
      clear_enqueued_jobs # the watch was killed before its job was queued
      expect(watch(after: 22.minutes)).to eq(outcome(resumed: [ run.id ]))
      expect(run.reload.scope).to include("resumes" => 2)
      perform_evaluation_jobs
      expect(run.reload.state).to eq("finished")
      expect_both_hosts_correct
    end

    it "fails a run after #{EvaluationRun::RESUMES} resumes with no progress, with the reason and its button on Data sources, " \
       "and its retry carries on from its batches once however often it is pressed" do
      run = import_curl
      perform_enqueued_jobs(only: EvaluationRunJob)
      one_batch_then_killed
      EvaluationRun::RESUMES.times do |n|
        expect(watch(after: (n + 1) * 11.minutes)).to eq(outcome(resumed: [ run.id ]))
        clear_enqueued_jobs # killed again before it ran
      end
      allow(FleetBroadcast).to receive(:refresh)
      expect(watch(after: 50.minutes)).to eq(outcome(failed: [ run.id ]))
      expect(run.reload).to have_attributes(state: "failed", batches_done: 1, scope: include("failure" => "stopped"))
      expect(run).to be_stopped
      expect(FleetBroadcast).to have_received(:refresh).once # what its first batch changed is refreshed as it fails
      expect(run.batches.count).to eq(1) # kept for its retry
      expect(EvaluationRun.shown_for_advisories).to eq(run)
      expect(watch(after: 70.minutes)).to eq(outcome) # failed: never resumed again

      stale = EvaluationRun.find(run.id) # a second press that read the run before the first committed
      expect { expect(EvaluationRun.retry!(run)).to eq(run) }.not_to change(EvaluationRun, :count)
      expect { expect(EvaluationRun.retry!(stale)).to eq(run) }.not_to change(EvaluationRun, :count)
      expect(run.reload).to have_attributes(state: "running", finished_at: nil)
      expect(run.scope.keys).not_to include(*EvaluationRun::WATCH_KEYS) # a fresh count, and no reason
      expect(enqueued_jobs.count { |job| job["job_class"] == "EvaluationRunJob" }).to eq(1)
      perform_evaluation_jobs
      expect(run.reload).to have_attributes(state: "finished", batches_done: 2, hosts_done: 2)
      expect_both_hosts_correct
    end

    it "reopens a run stopped before it was split, which carries on preparing from its checkpoint, once however often it is pressed (#295)" do
      run = import_curl
      clear_enqueued_jobs
      allow(VulnerabilityMatcher::Chunks).to receive(:restamp!).and_raise(SignalException, "TERM") # killed there every time
      killed! { run.fan_out! }
      expect(run.reload.prepare_step).to eq("restamp") # its chunks were matched
      EvaluationRun::RESUMES.times do |n|
        expect(watch(after: (n + 1) * 11.minutes)).to eq(outcome(resumed: [ run.id ]))
        clear_enqueued_jobs
        killed! { EvaluationRunJob.new(run.id).perform(run.id) } # perform alone: a killed worker runs no callback
      end
      expect(watch(after: 50.minutes)).to eq(outcome(failed: [ run.id ])) # the checkpoint never moved
      allow(VulnerabilityMatcher::Chunks).to receive(:restamp!).and_call_original
      stale = EvaluationRun.find(run.id)
      expect { expect(EvaluationRun.retry!(run)).to eq(run) }.not_to change(EvaluationRun, :count)
      expect { expect(EvaluationRun.retry!(stale)).to eq(run) }.not_to change(EvaluationRun, :count)
      expect(run.reload).to have_attributes(state: "queued", finished_at: nil, prepare_step: "restamp")
      expect(run.scope.keys).not_to include(*EvaluationRun::WATCH_KEYS)
      expect(enqueued_jobs.count { |job| job["job_class"] == "EvaluationRunJob" }).to eq(1)
      allow(VulnerabilityMatcher::Chunks).to receive(:ensure!).and_call_original
      perform_evaluation_jobs
      expect(VulnerabilityMatcher::Chunks).not_to have_received(:ensure!).with(anything, anything, hash_including(force: true)) # not prepared again
      expect(run.reload).to have_attributes(state: "finished", hosts_done: 2, prepare_step: "prepared")
      expect_both_hosts_correct
    end

    it "starts a run split with no batch left, which a retry cannot carry on, again as a new run" do
      run = import_curl
      clear_enqueued_jobs
      run.update_columns(state: "failed", started_at: Time.current, batch_count: 2, finished_at: Time.current)
      retried = nil
      expect { retried = EvaluationRun.retry!(run) }.to change(EvaluationRun, :count).by(1)
      expect(run.reload).to have_attributes(state: "superseded", superseded_by_id: retried.id)
      perform_evaluation_jobs
      expect(retried.reload).to have_attributes(state: "finished", hosts_done: 2)
      expect_both_hosts_correct
    end

    it "does not queue again the batches of a reopened run whose jobs are still queued (review of #292)" do
      run = import_curl
      perform_enqueued_jobs(only: EvaluationRunJob)
      queued, raised = run.batches.order(:position).pluck(:id)
      clear_enqueued_jobs
      live_job("EvaluationBatchJob", queued) # still waiting behind other work
      EvaluationRun.fail!(run.id) # the other batch raised every retry
      expect(EvaluationRun.retry!(run)).to eq(run)
      perform_enqueued_jobs(only: EvaluationRunJob)
      expect(batch_jobs.map { |job| job["arguments"] }).to eq([ [ raised ] ]) # not the one whose job is queued
      perform_evaluation_jobs
      EvaluationBatchJob.perform_now(queued) # its queued job, run at last
      expect(run.reload).to have_attributes(state: "finished", batches_done: 2, hosts_done: 2)
      expect_both_hosts_correct
    end

    it "never resumes a run that failed by raising every retry" do
      run = import_curl
      perform_enqueued_jobs(only: EvaluationRunJob)
      clear_enqueued_jobs
      EvaluationRun.fail!(run.id) # after_discard: a batch raised every retry
      expect(run.reload).not_to be_stopped
      expect(watch).to eq(outcome)
      expect(run.reload.state).to eq("failed")
    end

    it "leaves a run alone while its fan-out job is live, a retry pending included, or once running while a batch job is" do
      run = import_curl
      clear_enqueued_jobs
      fan_out = live_job("EvaluationRunJob", run.id)
      expect(watch).to eq(outcome)
      perform_enqueued_jobs(only: EvaluationRunJob) { run.fan_out! }
      clear_enqueued_jobs
      expect(watch(after: 22.minutes)).to eq(outcome) # running, but its fan-out's retry is pending
      fan_out.update!(finished_at: Time.current)
      batch = live_job("EvaluationBatchJob", run.batches.first.id)
      expect(watch(after: 22.minutes)).to eq(outcome)
      batch.update!(finished_at: Time.current)
      expect(watch(after: 22.minutes)).to eq(outcome(resumed: [ run.id ]))
    end

    it "resumes a re-match of how packages are matched (#270) killed between its batches" do
      import_curl
      EvaluationRun.delete_all # as if curl had been matched before how its packages are matched changed
      VulnerabilityFinding.where(package: %w[curl libcurl4]).delete_all
      run = EvaluationRun.start!("advisories", EvaluationRun::Advisories.matching_scope([ "curl" ]))
      perform_enqueued_jobs(only: EvaluationRunJob)
      one_batch_then_killed
      killed_job("EvaluationBatchJob", run.batches.pick(:id))
      expect(watch).to eq(outcome(resumed: [ run.id ]))
      perform_evaluation_jobs
      expect(run.reload).to have_attributes(state: "finished", batches_done: 2, hosts_done: 2)
      expect_both_hosts_correct
    end

    describe "killed at every point of its preparation (#295)" do
      include PreparationKills

      before do
        stub_const("EvaluationRun::Advisories::MATCH_PAGE", 1) # a checkpoint a chunk
        stub_const("VulnerabilityMatcher::Chunks::BATCH", 1)
      end

      # A new advisory for curl each time, so each run has real work to prepare.
      def import_curl_again(n)
        import_advisories(osv_record(id: "DSA-1-#{n}", package: "curl", fixed: "8.14.1-2"))
        EvaluationRun.where(kind: "advisories").order(:id).last
      end

      it "finishes whichever point it is killed at, with both hosts as a full re-match leaves them, each batched once" do
        dry = PreparationKills::Killer.new
        kill_with(dry)
        expect(drive_killed(import_curl_again(0), dry)).to eq(1)
        expect(dry.labels).to include("after checkpoint match:Debian:13", "after match_slice", "after checkpoint restamp", "after restamp!",
                                      "after checkpoint prepared", "before the batches are queued")
        (1..dry.labels.size).each do |point|
          killer = PreparationKills::Killer.new { |attempt, index, _| attempt == 1 && index == point }
          kill_with(killer)
          run = import_curl_again(point)
          expect(drive_killed(run, killer)).to eq(2), "killed at #{dry.labels[point - 1]}"
          expect_batched_once(run, 2)
          expect(run.scope).to include("stamp" => AdvisoryImport.newest_succeeded_id)
        end
        curl = Advisory.where("advisory_id LIKE 'DSA-1-%'").count
        expect(curl).to eq(dry.labels.size + 1)
        expect(VulnerabilityFinding.where(host: hosts.first).active.group(:package).count).to eq("curl" => curl) # each import's finding, on both hosts
        expect(VulnerabilityFinding.where(host: hosts.second).active.group(:package).count).to eq("libcurl4" => curl, "vim" => 1)
        expect { VulnerabilityMatcher.match_again! }.not_to(change { [ findings, evaluations ] })
      end

      it "is never failed when each attempt is killed as soon as it moves its checkpoint, since each move is progress" do
        killer = PreparationKills::Killer.new { |_, _, label| label.start_with?("after checkpoint") }
        kill_with(killer)
        run = import_curl_again(1)
        attempts = drive_killed(run, killer)
        expect(attempts).to be > EvaluationRun::RESUMES + 1 # more kills in a row than the watch allows without progress
        expect(run.reload.scope).not_to include("failure")
        expect_batched_once(run, 2)
        expect_both_hosts_correct
      end
    end
  end

  describe "a rule run" do
    let!(:rule) { define_cis_rules(cis_rule_hash).first }
    let!(:hosts) do
      [ enrolled_host.first.tap { |h| record_inventory(h) && record_config(h) },
        enrolled_host.first.tap { |h| record_inventory(h) && record_config(h, "sshd.permitrootlogin" => ok_fact("yes")) } ]
    end

    before { clear_enqueued_jobs }

    it "resumes a rule run killed between its batches, and both hosts get the edited rule's result" do
      CisResult.delete_all
      run = EvaluationRun.start!("cis_rules", "rule_ids" => [ rule.id ])
      perform_enqueued_jobs(only: EvaluationRunJob)
      one_batch_then_killed
      killed_job("EvaluationBatchJob", run.batches.pick(:id))
      expect(watch).to eq(outcome(resumed: [ run.id ]))
      perform_evaluation_jobs
      expect(run.reload).to have_attributes(state: "finished", batches_done: 2, hosts_done: 2)
      expect(CisResult.where(cis_rule: rule).order(:host_id).pluck(:host_id, :result)).to eq([ [ hosts.first.id, "pass" ], [ hosts.second.id, "fail" ] ])
      expect(EvaluationRun.shown_for_rule(rule.id)).to be_nil
    end
  end
end
