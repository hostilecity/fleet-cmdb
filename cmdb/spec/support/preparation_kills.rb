# Kills a fleet-wide run's preparation (#295) as a deploy's restart or the OOM killer would: SignalException, raised
# after a step's work committed or around a move of its checkpoint, with no job retry and no callback (Solid Queue
# fails a killed worker's job without either). Each kill is followed by EvaluationRunWatchJob's resume, until the run
# finishes. Specs then check that the hosts are as an unkilled run leaves them, and that each was batched once.
module PreparationKills
  # Counts the points where a worker can die in a run's fan-out, attempt by attempt, and raises at those the block
  # picks (|attempt, index, label|; index counts from 1 in each attempt). It is armed only while a fan-out runs, so the
  # batches' own matching is not counted.
  class Killer
    def initialize(&kill)
      @kill = kill || ->(*) { false }
      @attempt = 0
      @index = 0
      @labels = []
    end

    # The points of the first attempt, in order (a dry run, killed nowhere, lists every point there is).
    attr_reader :labels

    def next_attempt!
      @attempt += 1
      @index = 0
    end

    def armed
      @armed = true
      yield
    ensure
      @armed = false
    end

    def point!(label)
      return unless @armed

      @index += 1
      @labels << label if @attempt == 1
      raise SignalException, "TERM" if @kill.call(@attempt, @index, label)
    end
  end

  # Kills where killer says from now on. The kill points, installed once an example: before and after each move of the
  # checkpoint; after each matching or refresh transaction, the signals barrier, the restamp and the release of the
  # claims; and before the batches are queued (the split committed). Inside the test's transaction the barrier and the
  # release do what spec/support/signals.rb has them do there.
  def kill_with(killer)
    install_kill_points unless @kill_points
    @killer = killer
  end

  def install_kill_points
    @kill_points = true
    allow(EvaluationRun::Checkpoint).to receive(:for).and_wrap_original do |original, *args|
      original.call(*args).tap do |checkpoint|
        allow(checkpoint).to receive(:advance!).and_wrap_original do |advance, name, *rest, **options|
          @killer.point!("before checkpoint #{name}")
          advance.call(name, *rest, **options).tap { @killer.point!("after checkpoint #{name}") }
        end
      end
    end
    { VulnerabilityMatcher::Chunks => %i[match_slice signals_barrier! restamp!], VulnerabilityTriage::Base => %i[refresh_slice], TriageSignalChange => %i[release!] }.each do |target, names|
      names.each do |name|
        in_test = use_transactional_tests && SignalHelpers::IN_TEST_TRANSACTION[name]
        allow(target).to receive(name).and_wrap_original do |original, *args, **options|
          (in_test || original).call(*args, **options).tap { @killer.point!("after #{name}") }
        end
      end
    end
    allow(ActiveJob).to receive(:perform_all_later).and_wrap_original do |original, *args|
      @killer.point!("before the batches are queued")
      original.call(*args)
    end
  end

  # Runs the run's jobs as workers would, its fan-out killed where the killer says; after each kill, the watch resumes it
  # (10 minutes on). Returns how many attempts it took to finish. Fails if the run is failed or never finishes.
  def drive_killed(run, killer, limit: 40)
    clear_enqueued_jobs
    (1..limit).each do |attempt|
      killer.next_attempt!
      begin
        killer.armed { EvaluationRunJob.new(run.id).perform(run.id) } # perform alone: a killed worker runs no callback
        run_batches_alone
        return attempt if run.reload.state == "finished"
      rescue SignalException
        clear_enqueued_jobs # the worker died with them
      end
      expect(run.reload.state).not_to eq("failed")
      @watched = (@watched || 0) + 11
      outcome = travel(@watched.minutes) { EvaluationRunWatchJob.perform_now }
      return attempt if run.reload.state == "finished" # a split into no batch, finished by the watch

      expect(outcome["resumed"]).to include(run.id)
      clear_enqueued_jobs # its fan-out, run by the next attempt
    end
    raise "run #{run.id} did not finish in #{limit} attempts"
  end

  def run_batches_alone
    while (job = enqueued_jobs.find { |queued| queued["job_class"] == "EvaluationBatchJob" })
      enqueued_jobs.delete(job)
      batch_id = job["arguments"].first
      EvaluationBatchJob.new(batch_id).perform(batch_id)
    end
  end

  # Each host batched once: a batch a host (BATCH_SIZE 1), every batch counted, no batch left.
  def expect_batched_once(run, hosts)
    expect(run.reload).to have_attributes(state: "finished", batch_count: hosts, host_count: hosts, batches_done: hosts, hosts_done: hosts)
    expect(run.batches).to be_empty
  end
end
