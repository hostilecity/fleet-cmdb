# Exposure tier, points, and work items on the per-host summaries (VT-SCORES #262, FR-2.6, the epic's VT-M3 to VT-M5).
#
# - vulnerability_findings gains listener (smallint: 2 a process listening on the network loads its package, 1 one on
#   loopback only, NULL none or resolved), written by the host's transitions beside bucket, bucket_rule, and kev from
#   the same listener evidence rule N5 reads (owner decision 27: exposure points, more for a network listener), so a
#   score never depends on the clock at read time. Nullable with no default: metadata only, no rewrite.
# - host_compliance_summaries gains exposure_tier and exposure_points (NULL until the host is scored: evaluated, every
#   open finding triaged), vuln_kev_advisories, vuln_fix_critical, vuln_attention_undecided, the work items
#   (work_upgrades, work_kernel_install, work_reboot, and their sum work_items, NULL until scored), and the run's two
#   times (fixable_critical_since, no_fixable_critical_since). Version 4 of host_compliance_counts and of
#   host_compliance_summaries_refresh count them; vulnerability_exposure_points is the published points table; version
#   6 of host_compliance_summaries_changed also notes a finding whose rule, listener, or source changed, and the agent's
#   reboot flag (two triggers on host_applicability); version 3 of host_compliance_summaries_flush, with a trigger on
#   host_package_sets, ends a host's run after a gap in its package reports (review of #305, S4); and a trigger on
#   finding_decisions recounts a host whose decisions in force change, for vuln_attention_undecided (#298).
# - vulnerability_findings_listener_valid (listener 1 or 2, only beside a bucket) is added NOT VALID.
# - VT-FIXABLE's summary columns (vuln_fixable, vuln_fix_packages, vuln_fix_severities) are dropped: the triage buckets
#   replace them on the Compliance page and the fleet list (#281 item 1), and nothing reads them. The findings keep
#   their fix flag (last_fixed_version), which the host tab's ?fix=available reads.
#
# One transaction, touching only the summaries' columns (metadata only: a nullable column, or a constant default) and
# the functions and triggers. Every row reads "not scored" (NULL) until 20261123262002, or
# bin/rails compliance_summaries:recount_scores on a large database, recounts it: never a 0 that stands for data not
# counted yet. The progress of that recount is the one row of compliance_score_recounts (ComplianceFixRecount).
class AddExposureScores < ActiveRecord::Migration[8.1]
  NULLABLE = { exposure_tier: :smallint, exposure_points: :integer, work_upgrades: :integer, work_items: :integer,
               fixable_critical_since: :datetime, no_fixable_critical_since: :datetime }.freeze
  COUNTS = %i[vuln_kev_advisories vuln_fix_critical vuln_attention_undecided].freeze
  FLAGS = %i[work_kernel_install work_reboot].freeze
  DROPPED = { vuln_fixable: :integer, vuln_fix_packages: :integer, vuln_fix_severities: :smallint }.freeze
  FUNCTIONS = { host_compliance_counts: [ 4, 3 ], host_compliance_summaries_refresh: [ 4, 3 ], host_compliance_summaries_changed: [ 6, 5 ],
                host_compliance_summaries_flush: [ 3, 2 ], host_compliance_summaries_mark: [ 2, 1 ] }.freeze
  # Trigger => its table.
  TRIGGERS = { host_compliance_summaries_applicability_insert_delete: :host_applicability, host_compliance_summaries_applicability_update: :host_applicability,
               host_compliance_summaries_package_sets_gap: :host_package_sets, host_compliance_summaries_decisions: :finding_decisions }.freeze
  PROGRESS = "compliance_score_recounts".freeze

  def up
    add_column :vulnerability_findings, :listener, :smallint
    table, name, expression = VulnerabilityTriage::Checks::LISTENER
    add_check_constraint table, expression, name:, validate: false # reads no row; validated by 20261123262002
    NULLABLE.each { |name, type| add_column :host_compliance_summaries, name, type }
    COUNTS.each { |name| add_column :host_compliance_summaries, name, :integer, default: 0, null: false }
    FLAGS.each { |name| add_column :host_compliance_summaries, name, :boolean, default: false, null: false }
    execute "DROP FUNCTION host_compliance_counts(bigint[])" # its result columns change; the refresh that reads it is replaced below
    DROPPED.each_key { |name| remove_column :host_compliance_summaries, name }
    execute sql("functions/vulnerability_exposure_points_v01")
    FUNCTIONS.each { |name, (version, _)| execute sql("functions/#{name}_v#{format('%02d', version)}") }
    TRIGGERS.each_key { |name| execute sql("triggers/#{name}_v01") }
    create_progress
  end

  # The recount's progress: the last host id recounted (ComplianceFixRecount, table: PROGRESS). Also used by
  # 20261123262002's down.
  def create_progress
    create_table PROGRESS, id: :smallint do |t|
      t.bigint :last_host_id, null: false, default: 0
      t.check_constraint "id = 1", name: "#{PROGRESS}_one_row"
    end
    execute "INSERT INTO #{PROGRESS} (id, last_host_id) VALUES (1, 0)"
  end

  def down
    drop_table PROGRESS, if_exists: true
    TRIGGERS.each { |name, on| execute "DROP TRIGGER IF EXISTS #{name} ON #{on}" }
    execute "DROP FUNCTION host_compliance_counts(bigint[])"
    DROPPED.each { |name, type| add_column :host_compliance_summaries, name, type, default: 0, null: false } # 0 until compliance_summaries:rebuild
    FUNCTIONS.each { |name, (_, version)| execute sql("functions/#{name}_v#{format('%02d', version)}") }
    execute "DROP FUNCTION vulnerability_exposure_points(smallint, text, boolean, smallint)"
    (NULLABLE.keys + COUNTS + FLAGS).each { |name| remove_column :host_compliance_summaries, name }
    remove_check_constraint :vulnerability_findings, name: VulnerabilityTriage::Checks::LISTENER[1]
    remove_column :vulnerability_findings, :listener
  end

  private

  def sql(path) = Rails.root.join("db/#{path}.sql").read
end
