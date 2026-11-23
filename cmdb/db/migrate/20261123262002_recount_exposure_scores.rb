# After 20261123262001 (VT-SCORES #262), outside a transaction so agents keep reporting:
#
# 1. The fleet list's two sort indexes, built CONCURRENTLY so summary flushes go on meanwhile. An index left INVALID by
#    a build that stopped (the container killed mid-build) is dropped and built again, as #196's 20261116196002 does
#    (review of #305, S3); IF NOT EXISTS alone would keep it, and the sorts would read every summary.
# 2. vulnerability_findings_listener_valid validated, on a table of at most Checks::INLINE_BYTES; a larger one is left
#    NOT VALID for bin/rails vulnerabilities:validate_triage_checks (as 20261121259003).
# 3. Each finding's listener written in SQL from the listener evidence in force (ListenerBackfill), so no host is
#    counted in step 4 without its listener points (review of #305, S2).
# 4. Every host's summary recounted by the resumable ComplianceFixRecount (on compliance_score_recounts), then its
#    progress row dropped. As 20261120256002: steps 3 and 4 run inline only when their estimate is at most
#    INLINE_SECONDS; above that it
#    refuses with UPGRADE_STEP before recounting anything, and the operator runs bin/rails
#    compliance_summaries:recount_scores in the waiting container, then restarts it (docs/operations/upgrades.md).
#    The task does steps 3 and 4. Each attempt repeats steps 1 and 2, which find nothing left to do. Until a host is recounted its exposure and work
#    read "not scored", never 0.
class RecountExposureScores < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  INLINE_SECONDS = 90
  UPGRADE_STEP = "fleet-cmdb upgrade step needed".freeze
  RUNBOOK = "On the server VM, as the deploy user, recount in this waiting container, then restart it: " \
            "docker exec fleet-cmdb bin/rails compliance_summaries:recount_scores && docker restart fleet-cmdb (docs/operations/upgrades.md).".freeze
  ACTIVE = "CASE WHEN enrollment_state::text = 'active'::text THEN %s END".freeze
  IN_FLEET = "enrollment_state::text <> 'retired'::text".freeze
  # FleetList::RANKED's exposure and work keys, highest first, NULLs (not active or not scored) last, ties by name.
  INDEXES = {
    "host_compliance_summaries_exposure" => "(#{format(ACTIVE, 'exposure_tier')}) DESC NULLS LAST, (#{format(ACTIVE, 'exposure_points')}) DESC NULLS LAST, name_key, host_id",
    "host_compliance_summaries_work" => "(#{format(ACTIVE, 'work_items')}) DESC NULLS LAST, name_key, host_id"
  }.freeze
  def up
    INDEXES.each do |name, columns|
      drop_invalid(name)
      execute "CREATE INDEX CONCURRENTLY IF NOT EXISTS #{name} ON host_compliance_summaries (#{columns}) WHERE #{IN_FLEET}"
    end
    validate_listener_check
    upgrade
  end

  def down
    INDEXES.each_key { |name| execute "DROP INDEX CONCURRENTLY IF EXISTS #{name}" }
    require_relative "20261123262001_add_exposure_scores"
    AddExposureScores.new.create_progress unless table_exists?(AddExposureScores::PROGRESS)
  end

  private

  # Drops index if it is INVALID (a failed CONCURRENTLY build), so it is built again.
  def drop_invalid(index)
    invalid = select_value("SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = #{quote(index)} AND NOT i.indisvalid")
    execute "DROP INDEX CONCURRENTLY IF EXISTS #{quote_table_name(index)}" if invalid
  end

  def validate_listener_check
    table, name, = VulnerabilityTriage::Checks::LISTENER
    return if select_value("SELECT convalidated FROM pg_constraint WHERE conname = #{quote(name)} AND conrelid = #{quote(table)}::regclass")

    bytes = select_value("SELECT pg_relation_size(#{quote(table)}::regclass)").to_i
    return say("#{name}: left NOT VALID (#{bytes / 1.megabyte} MB); run bin/rails vulnerabilities:validate_triage_checks", true) if bytes > VulnerabilityTriage::Checks::INLINE_BYTES

    execute "ALTER TABLE #{quote_table_name(table)} VALIDATE CONSTRAINT #{quote_column_name(name)}"
  end

  # The listener backfill, then the recount, when both fit in INLINE_SECONDS; else the upgrade step, before either.
  def upgrade
    backfill = ListenerBackfill.new(log: ->(message) { say(message, true) })
    recount = ComplianceFixRecount.new(table: AddExposureScores::PROGRESS, log: ->(message) { say(message, true) })
    estimate = recount.estimate(within: INLINE_SECONDS)
    seconds = backfill.estimate + estimate.seconds
    if seconds > INLINE_SECONDS
      raise "#{UPGRADE_STEP}: writing the findings' listeners and recounting every host's exposure and work would take " \
            "#{too_long(estimate.with(seconds:))}, too long for container start; they read \"not scored\" until then. #{RUNBOOK}"
    end
    backfill.run!
    recount.run!
    drop_table AddExposureScores::PROGRESS, if_exists: true
  end

  def too_long(estimate)
    return "about #{(estimate.seconds / 60).ceil} min" if estimate.complete?

    "more than #{INLINE_SECONDS} s (it stopped counting there; docs/operations/upgrades.md has the rates)"
  end
end
