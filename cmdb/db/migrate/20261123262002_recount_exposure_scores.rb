# After 20261123262001 (VT-SCORES #262): the fleet list's two sort indexes, built concurrently so summary flushes keep
# going meanwhile; the hosts with listener evidence queued for their transitions, which write each finding's listener
# (a steady host's evidence changes nothing, so nothing else would); then every host's summary recounted by the
# resumable ComplianceFixRecount (on compliance_score_recounts), and its progress row dropped.
#
# As 20261120256002: the recount runs here, at container start, only when its estimate is at most INLINE_SECONDS.
# Above that it refuses with UPGRADE_STEP before it recounts anything; the operator runs
# bin/rails compliance_summaries:recount_scores in the waiting container, then restarts it (docs/operations/upgrades.md),
# and this migration then finds nothing left and finishes at once. Until a host is recounted its exposure and work read
# "not scored", never 0.
#
# Outside a transaction: each batch of 100 hosts commits with its progress, so a recount that stops partway carries on
# where it stopped.
class RecountExposureScores < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  INLINE_SECONDS = 90
  UPGRADE_STEP = "fleet-cmdb upgrade step needed".freeze
  RUNBOOK = "On the server VM, as the deploy user, recount in this waiting container, then restart it: " \
            "docker exec fleet-cmdb bin/rails compliance_summaries:recount_scores && docker restart fleet-cmdb (docs/operations/upgrades.md).".freeze
  ACTIVE = "CASE WHEN enrollment_state::text = 'active'::text THEN %s END".freeze
  IN_FLEET = "enrollment_state::text <> 'retired'::text".freeze
  # FleetList::SORTS' exposure and work keys, highest first, NULLs (not active or not scored) last, ties by name.
  INDEXES = {
    "host_compliance_summaries_exposure" => "(#{format(ACTIVE, 'exposure_tier')}) DESC NULLS LAST, (#{format(ACTIVE, 'exposure_points')}) DESC NULLS LAST, name_key, host_id",
    "host_compliance_summaries_work" => "(#{format(ACTIVE, 'work_items')}) DESC NULLS LAST, name_key, host_id"
  }.freeze
  LISTENER_BATCH = 1_000

  def up
    INDEXES.each do |name, columns|
      execute "CREATE INDEX CONCURRENTLY IF NOT EXISTS #{name} ON host_compliance_summaries (#{columns}) WHERE #{IN_FLEET}"
    end
    queue_listener_hosts
    recount
  end

  def down
    INDEXES.each_key { |name| execute "DROP INDEX CONCURRENTLY IF EXISTS #{name}" }
    require_relative "20261123262001_add_exposure_scores"
    AddExposureScores.new.create_progress unless table_exists?(AddExposureScores::PROGRESS)
  end

  private

  # The hosts whose stored findings may reflect listener evidence (HostApplicability#evidence_held), by the partial
  # index on host_applicability.
  def queue_listener_hosts
    ids = select_values("SELECT host_id FROM host_applicability WHERE library_scan = 'ran' AND jsonb_array_length(loaded_by_listeners) > 0 ORDER BY host_id")
    ids.map(&:to_i).each_slice(LISTENER_BATCH) { |slice| VulnerabilityMatchJob.perform_later(host_ids: slice) }
    say("queued the transitions of #{ids.size} hosts with listener evidence", true) if ids.any?
  end

  def recount
    recount = ComplianceFixRecount.new(table: AddExposureScores::PROGRESS, log: ->(message) { say(message, true) })
    estimate = recount.estimate(within: INLINE_SECONDS)
    if estimate.seconds > INLINE_SECONDS
      raise "#{UPGRADE_STEP}: recounting every host's exposure and work would take #{too_long(estimate)}, too long for container start; " \
            "they read \"not scored\" until then. #{RUNBOOK}"
    end
    recount.run!
    drop_table AddExposureScores::PROGRESS, if_exists: true
  end

  def too_long(estimate)
    return "about #{(estimate.seconds / 60).ceil} min" if estimate.complete?

    "more than #{INLINE_SECONDS} s (it stopped counting there; docs/operations/upgrades.md has the rates)"
  end
end
