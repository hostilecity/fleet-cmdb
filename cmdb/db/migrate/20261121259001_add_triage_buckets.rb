# Triage buckets for open findings (VT-BUCKETS #259, FR-2.6, ADR 0032, VT-S05).
#
# - chunk_matches gains the base bucket of each verdict (base_bucket, base_rule, kev, and triage_fixed_version, rule
#   F2's version): the rules that do not depend on the host, computed when a chunk is matched or re-triaged.
# - vulnerability_findings gains bucket, bucket_rule (smallints: VulnerabilityTriage::BUCKETS and RULE_IDS), and kev,
#   null while resolved, written by the host's transitions. Nullable columns with no default: metadata only, no rewrite
#   of the biggest table. Their checks are added NOT VALID, so adding them reads no row; every row written from now on
#   is checked (a rule belongs to one bucket, all three are set together, and a resolved finding has none).
# - host_compliance_summaries gains vuln_fix, vuln_attention, vuln_low_risk, vuln_ignorable (they add up to vuln_open)
#   and vuln_kev_open, counted by version 3 of host_compliance_counts and of host_compliance_summaries_refresh;
#   version 5 of host_compliance_summaries_changed also notes a finding whose bucket or KEV flag changed.
# - vulnerability_work_events (time-partitioned weekly on occurred_at, ADR 0027; kept 90 days) records the work a
#   host's reports show done.
# - evaluation_runs may be of kind triage (EvaluationRun::Triage); triage_run_chunks holds a run's changed chunks.
# - triage_signal_changes may hold tracker changes (one row per CVE, kind tracker).
#
# Every finding and summary reads "no bucket" (0 in the counts) until the run 20261121259002 queues has triaged them.
class AddTriageBuckets < ActiveRecord::Migration[8.1]
  SUMMARY = %i[vuln_fix vuln_attention vuln_low_risk vuln_ignorable vuln_kev_open].freeze
  FUNCTIONS = { host_compliance_counts: [ 3, 2 ], host_compliance_summaries_refresh: [ 3, 2 ], host_compliance_summaries_changed: [ 5, 4 ] }.freeze
  # A rule's bucket (VulnerabilityTriage::RULES): Fix available 1, Needs attention 2, Low risk 3, Ignorable 4.
  RULE_BUCKET = "CASE WHEN %<rule>s IN (3, 4, 5, 6) THEN 1 WHEN %<rule>s IN (10, 11, 13, 14) THEN 2 " \
                "WHEN %<rule>s IN (9, 15, 16, 17, 18, 19) THEN 3 WHEN %<rule>s IN (1, 2, 7, 8, 12) THEN 4 END"

  def up
    add_column :chunk_matches, :base_bucket, :smallint
    add_column :chunk_matches, :base_rule, :smallint
    add_column :chunk_matches, :kev, :boolean
    add_column :chunk_matches, :triage_fixed_version, :string, limit: 256
    add_check_constraint :chunk_matches, "(base_rule IS NULL) = (base_bucket IS NULL) AND (base_rule IS NULL) = (kev IS NULL) AND " \
                                         "(base_rule IS NULL OR base_bucket = #{format(RULE_BUCKET, rule: 'base_rule')})",
                         name: "chunk_matches_base_valid", validate: false

    add_column :vulnerability_findings, :bucket, :smallint
    add_column :vulnerability_findings, :bucket_rule, :smallint
    add_column :vulnerability_findings, :kev, :boolean
    add_check_constraint :vulnerability_findings, "(bucket_rule IS NULL) = (bucket IS NULL) AND (bucket_rule IS NULL) = (kev IS NULL) AND " \
                                                  "(bucket_rule IS NULL OR (state <> 'resolved' AND bucket = #{format(RULE_BUCKET, rule: 'bucket_rule')}))",
                         name: "vulnerability_findings_bucket_valid", validate: false

    SUMMARY.each { |name| add_column :host_compliance_summaries, name, :integer, default: 0, null: false }
    execute "DROP FUNCTION host_compliance_counts(bigint[])" # its result columns change
    FUNCTIONS.each { |name, (version, _)| execute function_sql(name, version) }

    replace_check :evaluation_runs, "evaluation_runs_kind_valid", "kind IN ('cis_rules', 'advisories', 'triage')"
    replace_check :triage_signal_changes, "triage_signal_changes_kind_valid", "kind IN ('kev', 'kev_all', 'epss', 'advisory', 'tracker')"
    replace_check :triage_signal_changes, "triage_signal_changes_target_valid",
                  "(kind IN ('kev', 'epss', 'tracker')) = (cve_id IS NOT NULL) AND (kind = 'advisory') = (advisory_id IS NOT NULL)"

    create_table :triage_run_chunks, primary_key: %i[evaluation_run_id package_chunk_id] do |t|
      t.bigint :evaluation_run_id, null: false
      t.bigint :package_chunk_id, null: false
    end
    add_foreign_key :triage_run_chunks, :evaluation_runs, on_delete: :cascade

    create_table :vulnerability_work_events, primary_key: %i[id occurred_at], options: "PARTITION BY RANGE (occurred_at)" do |t|
      t.bigserial :id, null: false
      t.bigint :host_id, null: false
      t.string :kind, limit: 16, null: false
      t.string :subject, limit: 256, null: false
      t.integer :findings_cleared, null: false
      t.datetime :occurred_at, null: false
      t.check_constraint "kind IN ('upgrade', 'kernel_installed', 'reboot')", name: "vulnerability_work_events_kind_valid"
      t.check_constraint "findings_cleared > 0", name: "vulnerability_work_events_cleared_positive"
    end
    add_index :vulnerability_work_events, %i[host_id occurred_at]
    add_index :vulnerability_work_events, :occurred_at
  end

  def down
    drop_table :vulnerability_work_events
    drop_table :triage_run_chunks
    replace_check :triage_signal_changes, "triage_signal_changes_target_valid",
                  "(kind IN ('kev', 'epss')) = (cve_id IS NOT NULL) AND (kind = 'advisory') = (advisory_id IS NOT NULL)"
    replace_check :triage_signal_changes, "triage_signal_changes_kind_valid", "kind IN ('kev', 'kev_all', 'epss', 'advisory')"
    replace_check :evaluation_runs, "evaluation_runs_kind_valid", "kind IN ('cis_rules', 'advisories')"
    execute "DROP FUNCTION host_compliance_counts(bigint[])"
    FUNCTIONS.each { |name, (_, version)| execute function_sql(name, version) }
    SUMMARY.each { |name| remove_column :host_compliance_summaries, name }
    remove_check_constraint :vulnerability_findings, name: "vulnerability_findings_bucket_valid"
    %i[bucket bucket_rule kev].each { |name| remove_column :vulnerability_findings, name }
    remove_check_constraint :chunk_matches, name: "chunk_matches_base_valid"
    %i[base_bucket base_rule kev triage_fixed_version].each { |name| remove_column :chunk_matches, name }
  end

  private

  def replace_check(table, name, expression)
    remove_check_constraint table, name: name
    add_check_constraint table, expression, name: name
  end

  def function_sql(name, version) = Rails.root.join("db/functions/#{name}_v#{format('%02d', version)}.sql").read
end
