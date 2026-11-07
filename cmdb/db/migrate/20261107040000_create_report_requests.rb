# On-demand report requests (P2-CONFIG-REPORTS, P2-S03, FR-2.1, DEC-13): an operator asks a host's agent for a
# fresh report of one type (config, packages, or inventory). The next heartbeat carries the outstanding types
# as the report_request directive (DEC-20) until a report of that type, collected after the request, arrives
# (satisfied) or the request passes expires_at (expired). A request is never deleted when it ends: its state
# and time say how it ended, and Retention prunes rows past the retention window.
#
# - At most one pending request per host and type (a partial unique index), so the directive and the clearing
#   are simple and concurrent requests cannot both create one.
# - sent_at is when a heartbeat first carried the request, so the host page can tell "waiting for the agent"
#   from "the agent has been asked".
class CreateReportRequests < ActiveRecord::Migration[8.1]
  def change
    create_table :report_requests do |t|
      t.references :host, null: false, foreign_key: true, index: false
      t.string :report_type, null: false, limit: 16
      t.string :state, null: false, default: "pending", limit: 16
      t.references :requested_by, null: false, foreign_key: { to_table: :operators }, index: false
      t.datetime :requested_at, null: false # server clock, like every time here
      t.datetime :expires_at, null: false
      t.datetime :sent_at
      t.datetime :satisfied_at
      t.uuid :satisfied_by_report_id
      t.datetime :expired_at
    end
    add_index :report_requests, %i[host_id report_type], unique: true, where: "state = 'pending'", name: "index_report_requests_one_pending"
    add_index :report_requests, %i[host_id requested_at]
    add_index :report_requests, :requested_at
    add_index :report_requests, :expires_at, where: "state = 'pending'", name: "index_report_requests_pending_expiry"
    add_check_constraint :report_requests, "report_type IN ('config', 'inventory', 'packages')", name: "report_requests_type_valid"
    add_check_constraint :report_requests, "state IN ('pending', 'satisfied', 'expired')", name: "report_requests_state_valid"
    add_check_constraint :report_requests, "(state = 'satisfied') = (satisfied_at IS NOT NULL AND satisfied_by_report_id IS NOT NULL)",
                         name: "report_requests_satisfied_matches_state"
    add_check_constraint :report_requests, "(state = 'expired') = (expired_at IS NOT NULL)", name: "report_requests_expired_matches_state"
    add_check_constraint :report_requests, "expires_at > requested_at", name: "report_requests_expire_after_request"
  end
end
