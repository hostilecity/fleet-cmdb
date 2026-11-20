# Whether each open finding has a fix, counted in the per-host summaries (VT-FIXABLE #256, FR-2.6; folds in #252,
# option a).
#
# The fix flag is not a column: an open or reopened finding has a fix exactly when its stored last_fixed_version is
# not NULL. The matcher's transitions already write last_fixed_version whenever an open finding's verdict gains,
# moves, or loses its fix (ADR 0028, "As built", item 6), so the flag is written in those statements, and nothing is
# added to vulnerability_findings: no rewrite of the biggest table (review of #267, B1). An advisory import that moves
# fixes runs EvaluationRun::Advisories, whose transitions write it: no separate recount.
#
# host_compliance_summaries gains vuln_fixable (open and reopened findings with a fix), vuln_fix_packages (distinct
# binary package and architecture among them), and vuln_fix_severities (a bit per severity with one, for the
# Compliance page's vuln=<severity>&fix=available). Version 2 of host_compliance_counts and of
# host_compliance_summaries_refresh count them, and version 4 of host_compliance_summaries_changed also notes a
# finding whose fix appeared or disappeared. A host that is not evaluated counts none (#252 question 6).
#
# One transaction, touching only the summaries (a metadata-only ADD COLUMN with a constant default) and the functions,
# so a summary flush never sees the counts function half replaced. Every row reads 0 until the next migration
# (20261120256002), or bin/rails compliance_summaries:recount_fixes on a large database, recounts it; the progress of
# that recount is the one row of compliance_fix_recounts, made here (ComplianceFixRecount).
class AddFixCountsToComplianceSummaries < ActiveRecord::Migration[8.1]
  COLUMNS = { vuln_fixable: :integer, vuln_fix_packages: :integer, vuln_fix_severities: :smallint }.freeze
  # Each function's version going up, and the one down restores.
  FUNCTIONS = { host_compliance_counts: [ 2, 1 ], host_compliance_summaries_refresh: [ 2, 1 ], host_compliance_summaries_changed: [ 4, 3 ] }.freeze

  def up
    COLUMNS.each { |name, type| add_column :host_compliance_summaries, name, type, default: 0, null: false }
    execute "DROP FUNCTION host_compliance_counts(bigint[])" # its result columns change
    FUNCTIONS.each { |name, (up, _down)| execute function_sql(name, up) }
    create_progress
  end

  # The recount's progress: the last host id recounted (ComplianceFixRecount). Also used by 20261120256002's down.
  def create_progress
    create_table :compliance_fix_recounts, id: :smallint do |t|
      t.bigint :last_host_id, null: false, default: 0
      t.check_constraint "id = 1", name: "compliance_fix_recounts_one_row"
    end
    execute "INSERT INTO compliance_fix_recounts (id, last_host_id) VALUES (1, 0)"
  end

  def down
    drop_table :compliance_fix_recounts, if_exists: true
    execute "DROP FUNCTION host_compliance_counts(bigint[])"
    FUNCTIONS.each { |name, (_up, down)| execute function_sql(name, down) }
    COLUMNS.each_key { |name| remove_column :host_compliance_summaries, name }
  end

  private

  def function_sql(name, version) = Rails.root.join("db/functions/#{name}_v#{format('%02d', version)}.sql").read
end
