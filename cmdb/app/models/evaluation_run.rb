# One fleet-wide evaluation (#197, P2-S06, P2-S11): a rule change re-evaluating rules on the fleet (cis_rules), an
# advisory import re-matching the hosts it affects (advisories), or a change of exploitation signals or Debian's
# triage re-triaging the hosts it affects (triage, VT-BUCKETS #259, EvaluationRun::Triage). The trigger starts a run once it commits; the run is
# split into batches of at most BATCH_SIZE hosts, keyset ranges of host ids, each a job on the evaluation queue
# (EvaluationRunJob fans out, EvaluationBatchJob runs a batch), so several workers share the work and a failed batch
# is retried alone.
#
# - Only affected hosts are batched: for an import, those on a package set holding a chunk with a changed source, or
#   with no evaluation with data yet, after the changed chunks are matched again (EvaluationRun::Advisories, ADR 0028); for a rule change, every host in the fleet, and
#   CisEvaluation reads facts only where a changed rule applies (EvaluationRun::CisRules).
# - Retry-safe: evaluation and matching are idempotent, and a batch row is deleted when its batch is counted, under the
#   run's row lock, so a retried or duplicated batch counts once. A batch locks its hosts in id order, in short
#   transactions of its own (CisEvaluation, VulnerabilityMatcher), never one long one.
# - Latest wins: a run supersedes the unfinished and failed runs of its kind that it covers (the same rules, or the
#   same sources), whose remaining batches then do nothing. Results are read under the host lock, so an older run's
#   batch still working writes the newer rule's results anyway.
# - Failed: when the fan-out or a batch fails every retry (after_discard on their jobs), the run stops: it keeps its
#   remaining batches, whose jobs check its state and do nothing, and it is failed, which ends its progress line. The
#   page says so, with a button that starts it again (EvaluationRunsController#retry, EvaluationRun.retry!: a run with
#   batches left carries on from them), and a later run that covers it supersedes it.
# - Killed (#278): Solid Queue fails the job of a worker that was killed (a deploy's restart past the shutdown timeout,
#   the OOM killer) without a retry, so after_discard never runs. EvaluationRunWatchJob resumes a run whose jobs are
#   gone from what it recorded (its fan-out again, or its remaining batches), and fails it, with the reason "stopped",
#   after RESUMES resumes in a row with no progress.
# - Preparation (#295): a queued run's preparation records a checkpoint as it goes (EvaluationRun::Checkpoint: the
#   step it reached and the last chunk id it handled), so a resume, or the retry of a run never split, carries on from
#   it. The split that follows is one transaction, so a run's batches are all there or none are.
# - Progress: batches_done of batch_count and hosts_done of host_count, shown where the run was triggered (the rule page,
#   the Advisory data sources page). The dashboard refreshes once when the run finishes, if what it shows changed.
# - Runs finished or superseded more than KEPT ago are deleted when a run starts; a failed run is kept until a later
#   run supersedes it, so a fleet left part-checked stays visible.
class EvaluationRun < ApplicationRecord
  KINDS = %w[cis_rules advisories triage].freeze
  STATES = %w[queued running finished superseded failed].freeze
  UNFINISHED = %w[queued running].freeze
  # A later run that covers one of these supersedes it.
  SUPERSEDABLE = (UNFINISHED + %w[failed]).freeze
  BATCH_SIZE = 1_000
  KEPT = 30.days
  # How many times in a row EvaluationRunWatchJob resumes a run whose job died with no progress since the last resume,
  # before it fails the run. A resume after progress (a batch counted, the run split, or its preparation's checkpoint
  # moved, #295) starts the count again, so a long run survives any number of deploys, as long as each attempt moves
  # it on (reviews of #277).
  RESUMES = 3
  # What EvaluationRunWatchJob keeps in a run's scope: how many resumes in a row made no progress, the progress
  # ([state, batches done]) at the last one, and why it failed the run ("failure" => "stopped"). A retry drops them.
  WATCH_KEYS = %w[resumes resume_progress failure].freeze

  has_many :batches, class_name: "EvaluationBatch", inverse_of: :evaluation_run, dependent: :delete_all
  # A triage run's changed chunks (deleted with the run by the foreign key).
  has_many :triage_chunks, class_name: "TriageRunChunk", inverse_of: :evaluation_run
  belongs_to :superseded_by, class_name: "EvaluationRun", optional: true

  validates :kind, inclusion: { in: KINDS }
  validates :state, inclusion: { in: STATES }

  scope :unfinished, -> { where(state: UNFINISHED) }

  # Starts a run once the trigger's transaction has committed, so the run sees what it was started for.
  def self.after_commit_start(kind, scope) = ActiveRecord.after_all_transactions_commit { start!(kind, scope) }

  def self.start!(kind, scope)
    where(state: %w[finished superseded]).where(finished_at: ...KEPT.ago).delete_all
    run = create!(kind:, scope:)
    EvaluationRunJob.perform_later(run.id)
    run
  end

  # The run to show on the rule's page: the newest run evaluating the rule, when it is unfinished or failed.
  def self.shown_for_rule(rule_id)
    run = where(kind: "cis_rules").where("scope -> 'rule_ids' @> ?", [ rule_id ].to_json).order(id: :desc).first
    run if run&.shown?
  end

  # The run to show on the Advisory data sources page: the newest unfinished re-matching or re-triage run, or else the
  # newest failed one (a later run covering it would have superseded it).
  def self.shown_for_advisories
    runs = where(kind: %w[advisories triage]).order(id: :desc)
    runs.unfinished.first || runs.find_by(state: "failed")
  end

  # Stops a run whose fan-out or a batch failed every retry (the jobs' after_discard): fail_locked!.
  def self.fail!(run_id)
    transaction do
      run = lock.find_by(id: run_id)
      next unless run&.unfinished?

      run.fail_locked!
    end
  end

  # Fails this run, whose row the caller has locked. It keeps its remaining batches, so its retry carries on from them
  # (EvaluationRun.retry!); their jobs check the state and do nothing meanwhile. What its finished batches changed is
  # refreshed. failure: why, when it is not a job failing every retry ("stopped": EvaluationRunWatchJob).
  def fail_locked!(failure: nil)
    self.scope = scope.merge("failure" => failure) if failure
    self.state = "failed"
    self.finished_at = Time.current
    FleetBroadcast.refresh if shown_changed
    save!
  end

  # Starts a failed run again (the button on its page), with a fresh resume count, all under the run's row lock, so a
  # second press, even one that read the run as failed before the first committed, finds it no longer failed and
  # changes nothing (fifth review of #277). A run with batches left (it was split, so prepared) is reopened and carries
  # on from them, as a resume does, so a failed run of a million hosts does not start from scratch; the batches whose
  # jobs are still queued (a run failed by one batch raising every retry) are not queued again by its fan-out. A run
  # never split is reopened as queued, and carries on preparing from its checkpoint (#295). Any other (split, with no
  # batch left) is superseded at once by a new run from its scope. Returns the run that now carries the work.
  def self.retry!(run)
    transaction do
      locked = lock.find(run.id)
      next locked unless locked.failed?

      scope = locked.scope.except(*WATCH_KEYS)
      if locked.carries_on?
        locked.update!(state: "running", finished_at: nil, scope:)
        ActiveRecord.after_all_transactions_commit { EvaluationRunJob.perform_later(locked.id) }
        next locked
      end

      if locked.started_at.nil? # never split: it carries on preparing from its checkpoint (#295), then is split
        locked.update!(state: "queued", finished_at: nil, scope:)
        ActiveRecord.after_all_transactions_commit { EvaluationRunJob.perform_later(locked.id) }
        next locked
      end

      retried = create!(kind: locked.kind, scope:)
      locked.update!(state: "superseded", superseded_by: retried, finished_at: Time.current)
      Triage.drop_sets([ locked.id ]) if locked.kind == "triage"
      ActiveRecord.after_all_transactions_commit { EvaluationRunJob.perform_later(retried.id) }
      retried
    end
  end

  def work
    case kind
    when "cis_rules" then CisRules.new(scope)
    when "triage" then Triage.new(scope, id)
    else Advisories.new(scope)
    end
  end

  def unfinished? = UNFINISHED.include?(state)

  def failed? = state == "failed"

  # Whether a failed run's retry carries on from the batches it had left (it was split, so prepared), rather than
  # starting over as a new run (EvaluationRun.retry!; its button says which, EvaluationRunsHelper::RETRY_TEXT).
  def carries_on? = batches.exists?

  # Failed by EvaluationRunWatchJob: its job was stopped RESUMES + 1 times in a row with no progress.
  def stopped? = failed? && scope["failure"] == "stopped"

  def shown? = unfinished? || failed?

  # Splits a queued run into batches and supersedes the older runs it covers (EvaluationRunJob). A retried fan-out
  # enqueues the batches still waiting again; a duplicated batch job counts once.
  def fan_out!
    # A running run's fan-out again (a resume, a retry that reopened it, a fan-out retried after its split) leaves out
    # the batches that still have a live job: a reopened run's other batches may still be queued (review of #292).
    again = state == "running"
    # The work's own preparation, before the hosts are found (an import matches its changed chunks, ADR 0028); outside
    # the run's lock, since it can take a while. Idempotent, and it carries on from its checkpoint (#295), so a retried
    # or resumed fan-out runs only what is left of it. A preparation that finds the checkpoint moved by another (or the
    # run no longer queued) stops, and leaves the run to it.
    if state == "queued"
      begin
        prepared = work.then { |w| w.prepare!(Checkpoint.for(self, w.prepare_steps)) }
      rescue Checkpoint::Lost => e
        Rails.logger.warn("[evaluation] #{kind} run #{id}: #{e.message}: this preparation stops")
        return
      end
      update!(scope: prepared) if kind == "triage" # the chunks it recorded, so its batches and a retry find its hosts
    end
    batch_ids = transaction do
      candidates = self.class.where(kind:, state: SUPERSEDABLE).where(id: ...id).select { |run| work.covers?(run.work) }.map(&:id)
      # Every run row this takes, in id order, so two fan-outs never deadlock (this run has the highest id). The states
      # are read again under the locks: a candidate that finished meanwhile is left alone (review of #204).
      locked = self.class.where(id: candidates + [ id ]).order(:id).lock.to_a
      older = locked.select { |run| run.id != id && SUPERSEDABLE.include?(run.state) }.map(&:id)
      reload
      next [] unless unfinished?

      # A fan-out that started on a queued run and finds it split already is a second one (the first split it): it
      # queues only the batches with no live job, as a fan-out again does.
      again ||= state == "running"
      split! if state == "queued"
      supersede!(older)
      batches.order(:position).pluck(:id)
    end
    batch_ids -= self.class.live_jobs["EvaluationBatchJob"].to_a if again && batch_ids.any?
    ActiveJob.perform_all_later(batch_ids.map { |batch_id| EvaluationBatchJob.new(batch_id) }) if batch_ids.any?
    finish_empty!
  end

  # { job class => Set of the first argument (a run or batch id) } of the live Solid Queue jobs of a run: neither
  # finished nor failed, so claimed, ready, scheduled (a retry pending) or blocked. EvaluationRunWatchJob reads them to
  # tell a dead run from a live one; a fan-out again, to queue only the batches with none.
  JOBS = %w[EvaluationRunJob EvaluationBatchJob].freeze

  def self.live_jobs
    jobs = SolidQueue::Job.where(class_name: JOBS, finished_at: nil).where.missing(:failed_execution).pluck(:class_name, :arguments)
    jobs.each_with_object(Hash.new { |h, k| h[k] = Set.new }) do |(name, arguments), live|
      live[name] << Array(arguments.is_a?(Hash) ? arguments["arguments"] : nil).first
    end
  end

  # Counts a finished batch (EvaluationBatchJob): once, under the run's row lock, deleting the batch row. A batch whose
  # run no longer counts it (superseded meanwhile) refreshes the dashboard for what it changed itself.
  def self.batch_done!(batch, changed_host_ids)
    transaction do
      run = lock.find_by(id: batch.evaluation_run_id)
      unless run&.state == "running" && EvaluationBatch.where(id: batch.id).delete_all == 1
        FleetBroadcast.hosts_changed(changed_host_ids)
        next
      end

      run.batches_done += 1
      run.hosts_done += batch.host_count
      run.shown_changed ||= changed_host_ids.any?
      run.finish! if run.batches_done >= run.batch_count
      run.save!
    end
  end

  def finish!
    Triage.drop_sets([ id ]) if kind == "triage"
    self.state = "finished"
    self.finished_at = Time.current
    FleetBroadcast.refresh if shown_changed || work.refresh_always?
  end

  private

  def split!
    ranges = self.class.connection.select_rows(<<~SQL.squish)
      SELECT min(id), max(id), count(*) FROM (
        SELECT id, (row_number() OVER (ORDER BY id) - 1) / #{BATCH_SIZE.to_i} AS position FROM (#{work.hosts.select(:id).to_sql}) hosts
      ) numbered GROUP BY position ORDER BY position
    SQL
    rows = ranges.each_with_index.map do |(first, last, count), position|
      { evaluation_run_id: id, position:, first_host_id: first, last_host_id: last, host_count: count }
    end
    EvaluationBatch.insert_all(rows) if rows.any?
    update!(state: "running", started_at: Time.current, batch_count: rows.size, host_count: rows.sum { |row| row[:host_count] })
  end

  def supersede!(older)
    return if older.empty?

    superseded = self.class.where(id: older)
    self.shown_changed ||= superseded.where(shown_changed: true, state: UNFINISHED).exists? # a failed run refreshed when it failed
    EvaluationBatch.where(evaluation_run_id: older).delete_all
    Triage.drop_sets(older) if kind == "triage"
    superseded.update_all(state: "superseded", superseded_by_id: id, finished_at: Time.current, updated_at: Time.current)
    save!
  end

  # A run with no hosts to evaluate finishes as it is split.
  def finish_empty!
    transaction do
      lock!
      next unless state == "running" && batch_count.zero?

      finish!
      save!
    end
  end
end
