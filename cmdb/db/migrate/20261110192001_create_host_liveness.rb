# Per-heartbeat host state in a narrow table of its own (#192, P-14 of the performance assessment, ADR 0029).
#
# Every heartbeat used to update the hosts row: about 600 bytes of heap, seven indexes (two of them GIN trigram, one
# GIN on tags), and a statement trigger with transition tables. Such an update is heap-only (HOT) only while its page
# has room, and every liveness change was a non-HOT update touching all seven indexes, because liveness_status was
# indexed. Now the columns a heartbeat changes every time, last_seen_at, liveness_status, and agent_reported_at, live in
# host_liveness: one row per host that has sent a heartbeat, about 60 bytes, no index but its primary key, so a
# heartbeat's update never changes an indexed column and is HOT whenever its page has room. The table keeps half of
# each page free for that (fillfactor 50) and is vacuumed after 1% of its rows are dead rather than 20%.
#
# The hosts columns a heartbeat carries but that rarely change (agent version, schema version, task capabilities,
# first_seen_at) stay on hosts, and a heartbeat writes them only when they change (Liveness.record_heartbeat!).
#
# The compliance summaries' status sort key now follows host_liveness: row triggers that fire only when the status
# changes (WHEN), so a steady heartbeat queues nothing. The hosts trigger no longer looks at liveness.
#
# One transaction, which takes the exclusive lock on hosts first: every later step needs it (the foreign key, dropping the
# columns), and taking a weaker lock first deadlocked against heartbeats on the scale benchmark (each heartbeat holds a
# row lock on hosts and waits to update it). Agents' writes wait while it runs: 0.3 s at 100,000 hosts on the benchmark, where no heartbeat waited over 0.4 s; if the lock is
# not granted within 10 s (a long transaction holds hosts), the migration stops, and can be run again. Down restores the
# columns and copies the rows back.
class CreateHostLiveness < ActiveRecord::Migration[8.1]
  # Half of each page free, for the next version of every row on it (see ADR 0029 for the measurements).
  STORAGE = "fillfactor = 50, autovacuum_vacuum_scale_factor = 0.01".freeze
  MOVED = "liveness_status, last_seen_at, agent_reported_at".freeze
  FUNCTIONS = %i[host_compliance_summaries_changed host_compliance_summaries_flush host_compliance_summaries_sync].freeze
  TRIGGERS = %i[host_compliance_summaries_liveness_insert_delete host_compliance_summaries_liveness_update host_liveness_no_truncate].freeze

  def up
    execute "SET LOCAL lock_timeout = '10s'"
    execute "LOCK TABLE hosts IN ACCESS EXCLUSIVE MODE"
    # Keyed by the host's id, with no sequence of its own.
    create_table :host_liveness, primary_key: :host_id, id: :bigint, default: nil, options: "WITH (#{STORAGE})" do |t|
      t.string :liveness_status, null: false
      t.datetime :last_seen_at, null: false # the server's clock, never the agent's (FR-1.2)
      t.datetime :agent_reported_at         # the agent's clock, stored, never used for liveness
      t.check_constraint "liveness_status::text = ANY (ARRAY['online'::text, 'stale'::text, 'offline'::text])", name: "host_liveness_status_valid"
    end
    # A host whose last_seen_at is unset has never sent a heartbeat ("awaiting first contact"): no row.
    execute "INSERT INTO host_liveness (host_id, #{MOVED}) SELECT id, COALESCE(liveness_status, 'online'), last_seen_at, agent_reported_at " \
            "FROM hosts WHERE last_seen_at IS NOT NULL"
    # The copied statuses are those the summaries already rank by, so the triggers come after the copy.
    FUNCTIONS.each { |name| execute Rails.root.join("db/functions/#{name}_v02.sql").read }
    TRIGGERS.each { |name| create_trigger name, on: :host_liveness }
    add_foreign_key :host_liveness, :hosts, column: :host_id
    remove_index :hosts, :liveness_status, name: "index_hosts_on_liveness_status"
    remove_check_constraint :hosts, name: "hosts_liveness_status_valid"
    remove_column :hosts, :liveness_status
    remove_column :hosts, :last_seen_at
    remove_column :hosts, :agent_reported_at
  end

  def down
    add_column :hosts, :liveness_status, :string
    add_column :hosts, :last_seen_at, :datetime
    add_column :hosts, :agent_reported_at, :datetime
    execute "UPDATE hosts h SET liveness_status = l.liveness_status, last_seen_at = l.last_seen_at, agent_reported_at = l.agent_reported_at " \
            "FROM host_liveness l WHERE l.host_id = h.id"
    add_check_constraint :hosts, "liveness_status IS NULL OR (liveness_status::text = ANY (ARRAY['online'::character varying::text, " \
                                 "'stale'::character varying::text, 'offline'::character varying::text]))", name: "hosts_liveness_status_valid"
    add_index :hosts, :liveness_status
    FUNCTIONS.each { |name| execute Rails.root.join("db/functions/#{name}_v01.sql").read }
    drop_table :host_liveness # its triggers go with it
  end
end
