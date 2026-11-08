# Tasks (FR-3.2, P3-S02). A batch is one operator request: the type, the validated parameters, how hosts were
# selected, the hosts it resolved to, and the ones excluded with why. It has one independent task per targeted
# host. Nothing here can hold a command: a task is a catalog type id and parameters that validated against that
# type's closed schema (FR-3.1, AC-3.2).
#
# The database enforces what must never happen whatever code writes the rows (tasks_guard, task_batches_guard):
# a batch never changes; a task starts queued, changes state only along the Task::TRANSITIONS table, never
# changes once it reaches a terminal state, and never changes its batch, host, type, parameters, expiry, or
# timeout; neither is ever deleted.
class CreateTaskBatchesAndTasks < ActiveRecord::Migration[8.1]
  STATES = %w[queued claimed running succeeded failed timed_out cancelled refused expired].freeze

  def change
    create_table :task_batches do |t|
      t.references :operator, null: false, foreign_key: true
      t.string :task_type, null: false, limit: 64
      t.jsonb :parameters, null: false, default: {}
      t.string :selection_method, null: false, limit: 16
      t.string :selection_tag, limit: 32
      t.bigint :selected_host_ids, array: true, null: false, default: []
      t.jsonb :excluded_hosts, null: false, default: []
      t.integer :confirmed_host_count
      t.integer :catalog_version, null: false
      t.string :catalog_digest, null: false, limit: 64
      t.datetime :created_at, null: false
    end
    add_check_constraint :task_batches, "selection_method IN ('explicit', 'tag')", name: "task_batches_selection_method"
    add_check_constraint :task_batches, "(selection_method = 'tag') = (selection_tag IS NOT NULL)", name: "task_batches_selection_tag"
    add_check_constraint :task_batches, "jsonb_typeof(parameters) = 'object'", name: "task_batches_parameters_object"
    add_check_constraint :task_batches, "octet_length(parameters::text) <= 8192", name: "task_batches_parameters_size"
    add_check_constraint :task_batches, "cardinality(selected_host_ids) BETWEEN 1 AND 25", name: "task_batches_selection_size"

    create_table :tasks do |t|
      t.uuid :uuid, null: false, default: -> { "gen_random_uuid()" }
      t.references :task_batch, null: false, foreign_key: true
      t.references :host, null: false, foreign_key: true, index: false
      t.string :task_type, null: false, limit: 64
      t.jsonb :parameters, null: false, default: {}
      t.string :state, null: false, default: "queued", limit: 16
      t.string :reason, limit: 32
      t.integer :timeout_seconds, null: false
      t.datetime :expires_at, null: false
      t.datetime :lease_expires_at
      t.datetime :claimed_at
      t.datetime :started_at
      t.datetime :finished_at
      t.integer :exit_status
      t.text :output
      t.boolean :output_truncated, null: false, default: false
      t.datetime :cancel_requested_at
      t.references :cancel_requested_by, foreign_key: { to_table: :operators }, index: false
      t.datetime :agent_started_at
      t.datetime :agent_finished_at
      t.timestamps
    end
    add_index :tasks, :uuid, unique: true
    add_index :tasks, [ :host_id, :state ]
    add_index :tasks, :expires_at, where: "state = 'queued'", name: "index_tasks_queued_by_expiry"
    add_index :tasks, :lease_expires_at, where: "state IN ('claimed', 'running')", name: "index_tasks_open_by_lease"
    add_check_constraint :tasks, "state IN (#{STATES.map { |s| "'#{s}'" }.join(', ')})", name: "tasks_state"
    add_check_constraint :tasks, "(state IN ('failed', 'refused')) = (reason IS NOT NULL)", name: "tasks_reason_for_failed_and_refused"
    add_check_constraint :tasks, "jsonb_typeof(parameters) = 'object'", name: "tasks_parameters_object"
    add_check_constraint :tasks, "octet_length(parameters::text) <= 8192", name: "tasks_parameters_size"
    add_check_constraint :tasks, "timeout_seconds BETWEEN 1 AND 86400", name: "tasks_timeout"
    add_check_constraint :tasks, "octet_length(output) <= 1048576", name: "tasks_output_size"

    create_function :task_batches_guard
    create_trigger :task_batches_immutable, on: :task_batches
    create_trigger :task_batches_no_truncate, on: :task_batches
    create_function :tasks_guard
    create_trigger :tasks_guard, on: :tasks
    create_trigger :tasks_no_truncate, on: :tasks
  end
end
