# One fleet-wide evaluation (#197, P2-S06, P2-S11): a rule change re-evaluating rules on the fleet (cis_rules), or an
# advisory import re-matching the hosts it affects (advisories). The trigger starts a run once it commits; the run is
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
# - Failed: when the fan-out or a batch fails every retry (after_discard on their jobs), the run stops: its remaining
#   batches are deleted and it is failed, which ends its progress line. The page says so, with a button that starts
#   the same run again (EvaluationRunsController#retry), and a later run that covers it supersedes it.
# - Progress: batches_done of batch_count and hosts_done of host_count, shown where the run was triggered (the rule page,
#   the Advisory data sources page). The dashboard refreshes once when the run finishes, if what it shows changed.
# - Runs finished or superseded more than KEPT ago are deleted when a run starts; a failed run is kept until a later
#   run supersedes it, so a fleet left part-checked stays visible.
class EvaluationRun < ApplicationRecord
  KINDS = %w[cis_rules advisories].freeze
  STATES = %w[queued running finished superseded failed].freeze
  UNFINISHED = %w[queued running].freeze
  # A later run that covers one of these supersedes it.
  SUPERSEDABLE = (UNFINISHED + %w[failed]).freeze
  BATCH_SIZE = 1_000
  KEPT = 30.days

  has_many :batches, class_name: "EvaluationBatch", inverse_of: :evaluation_run, dependent: :delete_all
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

  # The run to show on the Advisory data sources page: the newest unfinished re-matching run, or else the newest
  # failed one (a later run covering it would have superseded it).
  def self.shown_for_advisories
    runs = where(kind: "advisories").order(id: :desc)
    runs.unfinished.first || runs.find_by(state: "failed")
  end

  # Stops a run whose fan-out or a batch failed every retry (the jobs' after_discard). Its remaining batches are
  # deleted, so their jobs do nothing; what its finished batches changed is refreshed.
  def self.fail!(run_id)
    transaction do
      run = lock.find_by(id: run_id)
      next unless run&.unfinished?

      run.batches.delete_all
      run.state = "failed"
      run.finished_at = Time.current
      FleetBroadcast.refresh if run.shown_changed
      run.save!
    end
  end

  def work = (kind == "cis_rules" ? CisRules : Advisories).new(scope)

  def unfinished? = UNFINISHED.include?(state)

  def failed? = state == "failed"

  def shown? = unfinished? || failed?

  # Splits a queued run into batches and supersedes the older runs it covers (EvaluationRunJob). A retried fan-out
  # enqueues the batches still waiting again; a duplicated batch job counts once.
  def fan_out!
    # The work's own preparation, before the hosts are found (an import matches its changed chunks, ADR 0028); outside
    # the run's lock, since it can take a while. Idempotent, so a retried fan-out may run it again.
    work.prepare! if state == "queued"
    batch_ids = transaction do
      candidates = self.class.where(kind:, state: SUPERSEDABLE).where(id: ...id).select { |run| work.covers?(run.work) }.map(&:id)
      # Every run row this takes, in id order, so two fan-outs never deadlock (this run has the highest id). The states
      # are read again under the locks: a candidate that finished meanwhile is left alone (review of #204).
      locked = self.class.where(id: candidates + [ id ]).order(:id).lock.to_a
      older = locked.select { |run| run.id != id && SUPERSEDABLE.include?(run.state) }.map(&:id)
      reload
      next [] unless unfinished?

      split! if state == "queued"
      supersede!(older)
      batches.order(:position).pluck(:id)
    end
    ActiveJob.perform_all_later(batch_ids.map { |batch_id| EvaluationBatchJob.new(batch_id) }) if batch_ids.any?
    finish_empty!
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
