# Per-host compliance summaries for the fleet list and the compliance page (#193, P-05 of the performance assessment,
# ADR 0026).
#
# One row per host, made with the host and never deleted (hosts are retired, never deleted): its CIS-aligned pass,
# fail, and not readable counts, its open failures by severity, its open and reopened findings by severity, and whether
# its last matching run evaluated it, plus copies of the host's own fields the fleet list sorts and filters by. Both
# pages read a page of these rows in index order instead of aggregating every host's results and findings on every view
# (31 s and 29 s of database time at 100,000 hosts), and the fleet-wide counts are one sum over this narrow table.
#
# Triggers on hosts, host_inventories, cis_results, cis_rules (current version), vulnerability_findings, and
# host_vulnerability_evaluations only note the hosts a transaction changed (host_compliance_pending); one deferred
# constraint trigger syncs and recounts them at commit, locking their summary rows in one sorted statement
# (db/functions/host_compliance_summaries_flush_v01.sql). A new advisory severity queues the affected hosts
# (host_compliance_recounts) for ComplianceSummaryRecountJob, so an import never holds their rows. TRUNCATE is refused on
# the tables the counts come from.
#
# The derived columns are generated, so the pages' filters and sort keys are plain columns with indexes. Each fleet list
# sort has an index in each direction (name and hostname, nearly unique, one) with the name tie-break; worst first has
# its own. "Last seen" is the one sort without an index: last_seen_at changes on every heartbeat.
#
# No DDL transaction, so agents are never blocked for long (review of #206): the tables and functions; the triggers,
# each a short lock on its table, so writes from then on keep the rows right; every existing host filled in batches of
# 1,000, each its own transaction; the indexes built concurrently, after the fill; the foreign key added NOT VALID and
# validated afterwards. If it stops partway, run it down and up again. bin/rails compliance_summaries:check compares
# every row with a fresh count (docs/operations/compliance-summaries.md).
class CreateHostComplianceSummaries < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  COUNTED = "(cis_passed + cis_failed + cis_not_readable)".freeze
  OPEN = "(vuln_critical + vuln_high + vuln_medium + vuln_low + vuln_unknown)".freeze
  SHOWN = "(vuln_evaluated OR #{OPEN} > 0)".freeze
  IN_FLEET = "enrollment_state::text <> 'retired'::text".freeze
  BATCH = 1_000

  # Fleet list sorts with few distinct values need an index in each direction, with the name tie-break ascending in
  # both and NULLs last in both (FleetList::SORTS).
  BOTH_DIRECTIONS = { "status" => "status_rank DESC", "tags" => "tags_key DESC NULLS LAST", "agent" => "agent_key DESC NULLS LAST",
                      "os" => "lower(os_name) DESC NULLS LAST", "cis" => "fleet_cis_key DESC NULLS LAST",
                      "vulns" => "fleet_vulns_key DESC NULLS LAST" }.freeze

  FUNCTIONS = %i[host_compliance_status_rank host_compliance_counts host_compliance_summaries_refresh host_compliance_summaries_sync
                 host_compliance_summaries_mark host_compliance_summaries_flush host_compliance_summaries_changed
                 host_compliance_summaries_truncate_guard].freeze

  # Trigger (db/triggers/<name>_v01.sql) => its table. The flush first, so a change marked after it is recounted.
  TRIGGERS = { host_compliance_summaries_flush: :host_compliance_flushes,
               host_compliance_summaries_hosts_insert: :hosts, host_compliance_summaries_hosts_update: :hosts,
               host_compliance_summaries_inventory_insert_delete: :host_inventories, host_compliance_summaries_inventory_update: :host_inventories,
               host_compliance_summaries_evaluation_insert_delete: :host_vulnerability_evaluations,
               host_compliance_summaries_evaluation_update: :host_vulnerability_evaluations, host_compliance_summaries_rule_version: :cis_rules,
               host_compliance_summaries_cis_insert: :cis_results, host_compliance_summaries_cis_update: :cis_results,
               host_compliance_summaries_cis_delete: :cis_results, host_compliance_summaries_findings_insert: :vulnerability_findings,
               host_compliance_summaries_findings_update: :vulnerability_findings, host_compliance_summaries_findings_delete: :vulnerability_findings,
               host_compliance_summaries_advisories_update: :advisories,
               cis_results_no_truncate: :cis_results, vulnerability_findings_no_truncate: :vulnerability_findings,
               host_vulnerability_evaluations_no_truncate: :host_vulnerability_evaluations, host_inventories_no_truncate: :host_inventories }.freeze

  def up
    create_tables
    FUNCTIONS.each { |name| create_function name }
    TRIGGERS.each { |name, table| create_trigger name, on: table }
    fill
    create_indexes
    add_foreign_key :host_compliance_summaries, :hosts, validate: false
    validate_foreign_key :host_compliance_summaries, :hosts
  end

  def down
    TRIGGERS.each { |name, table| execute "DROP TRIGGER IF EXISTS #{name} ON #{table}" }
    FUNCTIONS.reverse_each { |name| execute "DROP FUNCTION IF EXISTS #{name} CASCADE" }
    execute "DROP INDEX CONCURRENTLY IF EXISTS index_cis_results_failing_without_version"
    %i[host_compliance_summaries host_compliance_pending host_compliance_flushes host_compliance_recounts].each { |table| drop_table table, if_exists: true }
  end

  private

  def create_tables
    # Keyed by the host's id, with no sequence of its own.
    create_table :host_compliance_summaries, primary_key: :host_id, id: :bigint, default: nil do |t|
      t.string :enrollment_state, limit: 16, null: false
      t.integer :status_rank, limit: 2, null: false
      t.text :name_key, null: false # lower(name) can be longer than name (ICU: lower('İ') is two characters)
      t.string :hostname, limit: 253, null: false
      t.text :tags_key
      t.decimal :agent_key, array: true
      t.text :os_name
      %i[cis_passed cis_failed cis_not_readable cis_critical cis_high cis_medium cis_low
         vuln_critical vuln_high vuln_medium vuln_low vuln_unknown].each { |column| t.integer column, null: false, default: 0 }
      t.boolean :vuln_evaluated, null: false, default: false
      t.virtual :cis_counted, type: :integer, as: COUNTED, stored: true
      t.virtual :vuln_open, type: :integer, as: OPEN, stored: true
      # The host page's pass rate, passed / (passed + failed + not readable) (Q3); NULL when no check counts.
      t.virtual :pass_rate, type: :decimal, as: "CASE WHEN #{COUNTED} > 0 THEN cis_passed::numeric / #{COUNTED} END", stored: true
      t.virtual :nothing_evaluated, type: :boolean, as: "#{COUNTED} = 0 AND NOT #{SHOWN}", stored: true
      # The fleet list's compliance columns: NULL (last in either direction) when not active or not evaluated.
      t.virtual :fleet_cis_key, type: :decimal, as: "CASE WHEN enrollment_state::text = 'active' AND #{COUNTED} > 0 THEN cis_passed::numeric / #{COUNTED} END",
                                stored: true
      t.virtual :fleet_vulns_key, type: :integer, as: "CASE WHEN enrollment_state::text = 'active' AND #{SHOWN} THEN #{OPEN} END", stored: true
      t.check_constraint "status_rank BETWEEN 0 AND 5", name: "host_compliance_summaries_status_rank"
    end
    # The hosts each open transaction changed, flushed and emptied at its commit; kinds is the bit set of
    # host_compliance_summaries_mark.
    create_table :host_compliance_pending, primary_key: %i[xact_id host_id] do |t|
      t.bigint :xact_id, null: false
      t.bigint :host_id, null: false
      t.integer :kinds, limit: 2, null: false
    end
    # One row for each open transaction with marked hosts: its insert queues the deferred flush.
    create_table :host_compliance_flushes, primary_key: :xact_id, id: :bigint, default: nil
    # Hosts whose counts an advisory's new severity moved, for ComplianceSummaryRecountJob.
    create_table :host_compliance_recounts, primary_key: :host_id, id: :bigint, default: nil do |t|
      t.datetime :queued_at, null: false, default: -> { "CURRENT_TIMESTAMP" }
    end
  end

  # Every existing host, in id order, a batch a transaction. Writes during the fill are synced by the triggers.
  def fill
    last = 0
    loop do
      ids = select_values("SELECT id FROM hosts WHERE id > #{last} ORDER BY id LIMIT #{BATCH}").map(&:to_i)
      break if ids.empty?

      list = "ARRAY[#{ids.join(',')}]::bigint[]"
      transaction do
        execute "SELECT host_compliance_summaries_sync(#{list})"
        execute "SELECT host_compliance_summaries_refresh(#{list})"
      end
      last = ids.last
    end
  end

  def create_indexes
    add = ->(columns, **options) { add_index :host_compliance_summaries, columns, algorithm: :concurrently, **options }
    add.(%i[name_key host_id], name: "host_compliance_summaries_name", where: IN_FLEET)
    add.(%i[hostname name_key host_id], name: "host_compliance_summaries_hostname", where: IN_FLEET)
    BOTH_DIRECTIONS.each do |sort, descending|
      add.("#{descending[/\A\S+/]}, name_key, host_id", name: "host_compliance_summaries_#{sort}", where: IN_FLEET)
      add.("#{descending}, name_key, host_id", name: "host_compliance_summaries_#{sort}_desc", where: IN_FLEET)
    end
    # Compliance, worst first (Q9): nothing evaluated last; most critical, high, medium, low (CIS and vulnerabilities
    # together), and unknown; lowest pass rate; name. Every key ascending, so a page boundary is one row comparison.
    add.("nothing_evaluated, (- (cis_critical + vuln_critical)), (- (cis_high + vuln_high)), (- (cis_medium + vuln_medium)), " \
         "(- (cis_low + vuln_low)), (- vuln_unknown), COALESCE(pass_rate, 2::numeric), name_key, host_id",
         name: "host_compliance_summaries_worst", where: "enrollment_state::text = 'active'::text")
    # Rule version changes look for failures that name no version; evaluation always names one, so this stays empty.
    add_index :cis_results, :cis_rule_id, name: "index_cis_results_failing_without_version", algorithm: :concurrently,
                                          where: "result::text = 'fail'::text AND cis_rule_version_id IS NULL"
  end
end
