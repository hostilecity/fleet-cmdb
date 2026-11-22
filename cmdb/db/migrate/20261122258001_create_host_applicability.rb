# What the agent reports about applicability (FR-2.6, VT-APPLICABILITY, #258): the reboot flag and the kernel build
# from the inventory, and what is in use from the package report (listening packages by class, running services'
# packages, unnamed listener counts, and the optional library scan's packages, stale ones, and those listening
# processes load). Triage (VT-BUCKETS, #277; VT-SCORES) reads it.
#
# Every list is positive evidence only; nothing is called idle from it (owner decision 2026-11-21). loaded_by_listeners
# holds [{ "listener" (a package or null), "service" (a unit or null), "class" ("network" or "loopback"), "sockets" (at
# most 4, "address:port/protocol"), "packages" }], one per listener and unit, sorted. library_scan_received_at is when
# the server first received a report carrying that scan (server clock): escalations expire 24 hours after it.
# loaded_by_listeners is NULL when the scan ran on a kernel that cannot tell which processes listen (before 5.14),
# kept apart from [] (it can, and none loads anything, or there was no scan).
#
# One narrow row per host, written only when what it holds changes (as hosts is after #220, ADR 0029): a steady fleet
# writes nothing here. No row means nothing reported. reboot_required is true or NULL, never false (Debian bug
# #1010699). A new table, so the migration takes no lock on a busy one.
class CreateHostApplicability < ActiveRecord::Migration[8.1]
  def change
    create_table :host_applicability, primary_key: :host_id, id: :bigint, default: nil do |t|
      t.boolean :reboot_required
      t.string :reboot_packages, array: true, null: false, default: []
      t.string :kernel_build, limit: 256
      t.datetime :reboot_changed_at
      t.boolean :in_use_reported, null: false, default: false
      t.string :listening_network, array: true, null: false, default: []
      t.string :listening_loopback, array: true, null: false, default: []
      t.string :running_services, array: true, null: false, default: []
      t.integer :unnamed_network, null: false, default: 0
      t.integer :unnamed_loopback, null: false, default: 0
      t.string :library_scan, limit: 8
      t.string :libraries, array: true, null: false, default: []
      t.string :stale_libraries, array: true, null: false, default: []
      t.jsonb :loaded_by_listeners, default: []
      t.datetime :library_scanned_at
      t.datetime :library_scan_received_at
      t.datetime :in_use_changed_at
      # TriageListenerExpiryJob asks for the hosts whose scan the server received in an hour's window.
      t.index :library_scan_received_at
      t.check_constraint "reboot_required IS NULL OR reboot_required", name: "host_applicability_reboot_true_or_null"
      t.check_constraint "library_scan IN ('off', 'ran', 'failed')", name: "host_applicability_library_scan_valid"
      t.check_constraint "in_use_reported = (library_scan IS NOT NULL)", name: "host_applicability_in_use_reported"
      t.check_constraint "loaded_by_listeners IS NULL OR jsonb_typeof(loaded_by_listeners) = 'array'",
                         name: "host_applicability_loaded_by_listeners_array"
    end
    add_foreign_key :host_applicability, :hosts, column: :host_id
  end
end
