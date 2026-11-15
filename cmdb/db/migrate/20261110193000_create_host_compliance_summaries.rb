# Per-host compliance summaries for the fleet list and the compliance page (#193, P-05 of the performance assessment).
#
# One row per host, made with the host and never deleted (hosts are retired, never deleted): its CIS-aligned pass,
# fail, and not readable counts, its open failures by severity, its open and reopened findings by severity, and whether
# its last matching run evaluated it, plus copies of the host's own fields the fleet list sorts and filters by. Both
# pages read a page of these rows in index order instead of aggregating every host's results and findings on every view
# (31 s and 29 s of database time at 100,000 hosts), and the fleet-wide counts are one sum over this narrow table.
#
# Triggers keep every row right in the transaction that changes what it is built from, whichever code writes it:
# hosts, host_inventories, cis_results, cis_rules (current version), vulnerability_findings, advisories (severity), and
# host_vulnerability_evaluations. A recount locks the host's row first, so two transactions changing one host at once
# leave the counts of both (db/functions/host_compliance_summaries_refresh_v01.sql).
#
# The derived columns are generated, so the pages' filters and sort keys are plain columns with indexes. Each fleet list
# sort has an index in each direction (name and hostname, nearly unique, one) with the name tie-break; worst first has
# its own. "Last seen" is the one sort without an index: last_seen_at changes on every heartbeat.
#
# The migration fills every existing host's row. bin/rails compliance_summaries:rebuild does it again in batches, and
# compliance_summaries:check compares every row with a fresh count (docs/operations/compliance-summaries.md).
class CreateHostComplianceSummaries < ActiveRecord::Migration[8.1]
  COUNTED = "(cis_passed + cis_failed + cis_not_readable)".freeze
  OPEN = "(vuln_critical + vuln_high + vuln_medium + vuln_low + vuln_unknown)".freeze
  SHOWN = "(vuln_evaluated OR #{OPEN} > 0)".freeze
  IN_FLEET = "enrollment_state::text <> 'retired'::text".freeze

  # Fleet list sorts with few distinct values need an index in each direction, with the name tie-break ascending in
  # both and NULLs last in both (FleetList::KEYS).
  BOTH_DIRECTIONS = { "status" => "status_rank DESC", "tags" => "tags_key DESC NULLS LAST", "agent" => "agent_key DESC NULLS LAST",
                      "os" => "lower(os_name) DESC NULLS LAST", "cis" => "fleet_cis_key DESC NULLS LAST",
                      "vulns" => "fleet_vulns_key DESC NULLS LAST" }.freeze

  # Trigger (db/triggers/host_compliance_summaries_<name>_v01.sql) => its table.
  TRIGGERS = { hosts_insert: :hosts, hosts_update: :hosts, inventory_insert_delete: :host_inventories, inventory_update: :host_inventories,
               evaluation_insert_delete: :host_vulnerability_evaluations, evaluation_update: :host_vulnerability_evaluations,
               rule_version: :cis_rules, cis_insert: :cis_results, cis_update: :cis_results, cis_delete: :cis_results,
               findings_insert: :vulnerability_findings, findings_update: :vulnerability_findings, findings_delete: :vulnerability_findings,
               advisories_update: :advisories }.freeze

  def up
    # Keyed by the host's id, with no sequence of its own.
    create_table :host_compliance_summaries, primary_key: :host_id, id: :bigint, default: nil do |t|
      t.string :enrollment_state, limit: 16, null: false
      t.integer :status_rank, limit: 2, null: false
      t.string :name_key, limit: 100, null: false
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
    end
    add_foreign_key :host_compliance_summaries, :hosts
    add_check_constraint :host_compliance_summaries, "status_rank BETWEEN 0 AND 5", name: "host_compliance_summaries_status_rank"

    add_index :host_compliance_summaries, %i[name_key host_id], name: "host_compliance_summaries_name", where: IN_FLEET
    add_index :host_compliance_summaries, %i[hostname name_key host_id], name: "host_compliance_summaries_hostname", where: IN_FLEET
    BOTH_DIRECTIONS.each do |sort, descending|
      add_index :host_compliance_summaries, "#{descending[/\A\S+/]}, name_key, host_id", name: "host_compliance_summaries_#{sort}", where: IN_FLEET
      add_index :host_compliance_summaries, "#{descending}, name_key, host_id", name: "host_compliance_summaries_#{sort}_desc", where: IN_FLEET
    end
    # Compliance, worst first (Q9): nothing evaluated last; most critical, high, medium, low (CIS and vulnerabilities
    # together), and unknown; lowest pass rate; name. Every key ascending, so a page boundary is one row comparison.
    add_index :host_compliance_summaries,
              "nothing_evaluated, (- (cis_critical + vuln_critical)), (- (cis_high + vuln_high)), (- (cis_medium + vuln_medium)), " \
              "(- (cis_low + vuln_low)), (- vuln_unknown), COALESCE(pass_rate, 2::numeric), name_key, host_id",
              name: "host_compliance_summaries_worst", where: "enrollment_state::text = 'active'::text"

    # Rule version changes look for failures that name no version; evaluation always names one, so this stays empty.
    add_index :cis_results, :cis_rule_id, name: "index_cis_results_failing_without_version", where: "result::text = 'fail'::text AND cis_rule_version_id IS NULL"

    create_function :host_compliance_counts
    create_function :host_compliance_summaries_refresh
    create_function :host_compliance_summaries_sync
    create_function :host_compliance_summaries_changed

    execute "SELECT host_compliance_summaries_sync(ARRAY(SELECT id FROM hosts))"
    execute "SELECT host_compliance_summaries_refresh(ARRAY(SELECT id FROM hosts))"

    TRIGGERS.each { |name, table| create_trigger :"host_compliance_summaries_#{name}", on: table }
  end

  def down
    TRIGGERS.each { |name, table| drop_trigger :"host_compliance_summaries_#{name}", on: table }
    drop_function :host_compliance_summaries_changed
    drop_function :host_compliance_summaries_sync
    drop_function :host_compliance_summaries_refresh
    drop_function :host_compliance_counts
    remove_index :cis_results, name: "index_cis_results_failing_without_version"
    drop_table :host_compliance_summaries
  end
end
