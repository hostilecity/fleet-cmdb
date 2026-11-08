# The distribution's own triage beside each finding (P2-S16, ADR 0022): the Debian Security Tracker's data, a
# second advisory data source beside OSV that annotates findings and never changes them.
#
# - triage_entries holds one row per tracker, release, source package, and CVE, as the last import that stored
#   that release left it. tracker is "debian" for now: another distribution's tracker is another value, not
#   another table (ADR 0022, item 4). urgency is normalised (nil for "not yet assigned" or none) beside the raw
#   text; no_dsa_reason is nil for a plain no-DSA, else Debian's reason ("postponed", "ignored").
# - triage_imports records every import (the scheduled refresh, or a file by hand) with its outcome and counts,
#   which is how freshness is known. releases lists the releases whose data it stored: a held-back release kept
#   its previous data, so it is not among them. removed_releases lists the releases it did not import because
#   no active host reports them (or the release table no longer lists them), whose stored data it deleted.
class CreateTriageEntries < ActiveRecord::Migration[8.1]
  def change
    create_table :triage_imports do |t|
      t.string :tracker, null: false, limit: 16
      t.string :origin, null: false, limit: 8
      t.string :source, null: false, limit: 256
      t.string :state, null: false, limit: 16
      t.string :releases, null: false, array: true, default: []
      t.string :removed_releases, null: false, array: true, default: []
      t.jsonb :counts, null: false, default: {}
      t.jsonb :problems, null: false, default: []
      t.string :reason, limit: 512
      t.string :etag, limit: 256
      t.string :last_modified, limit: 64
      t.references :operator, foreign_key: true
      t.datetime :started_at, null: false
      t.datetime :finished_at, null: false
    end
    add_index :triage_imports, %i[tracker finished_at]
    add_check_constraint :triage_imports, "origin IN ('feed', 'file')", name: "triage_imports_origin_valid"
    add_check_constraint :triage_imports, "state IN ('succeeded', 'failed', 'held_back')", name: "triage_imports_state_valid"

    create_table :triage_entries do |t|
      t.string :tracker, null: false, limit: 16
      t.string :release, null: false, limit: 32
      t.string :package, null: false, limit: 128
      t.string :cve_id, null: false, limit: 32
      t.string :status, null: false, limit: 16
      t.string :urgency, limit: 16
      t.string :urgency_raw, limit: 64
      t.string :fixed_version, limit: 256
      t.boolean :no_dsa, null: false, default: false
      t.string :no_dsa_note, limit: 512
      t.string :no_dsa_reason, limit: 32
      t.boolean :next_point_update, null: false, default: false
      t.string :scope, limit: 8
    end
    add_index :triage_entries, %i[tracker release package cve_id], unique: true, name: "index_triage_entries_unique"
    add_check_constraint :triage_entries, "status IN ('open', 'resolved', 'undetermined')", name: "triage_entries_status_valid"
    add_check_constraint :triage_entries, "urgency IN ('unimportant', 'low', 'medium', 'high', 'end-of-life')", name: "triage_entries_urgency_valid"
    add_check_constraint :triage_entries, "no_dsa OR (no_dsa_note IS NULL AND no_dsa_reason IS NULL)", name: "triage_entries_no_dsa_consistent"
  end
end
