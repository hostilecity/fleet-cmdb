# Task controls (P3-S05, P3-S06).
#
# task_allowed_services is the server's restart allowlist (DEC-15, owner decision Q31): full .service unit names,
# each for every host (tag NULL) or for the hosts with one tag. Empty until the owner adds a service. A service is
# listed once per scope; protected services are refused by the application before they get here (TaskSettings),
# and refused again when a task is created and claimed (TaskPolicy).
#
# tasks_guard v02 also keeps a cancel request (cancel_requested_at, cancel_requested_by_id) as recorded: set once,
# only on a running task and with the operator, never changed afterwards. And it allows queued -> failed, only with
# reason not_run: an agent closing a task it held and never ran, after its claim lapsed (P3-S05).
class CreateTaskAllowedServices < ActiveRecord::Migration[8.1]
  def change
    create_table :task_allowed_services do |t|
      t.string :service, null: false, limit: 64
      t.string :tag, limit: 32
      t.references :added_by, null: false, foreign_key: { to_table: :operators }, index: false
      t.datetime :created_at, null: false
    end
    add_index :task_allowed_services, %i[service tag], unique: true, nulls_not_distinct: true
    add_check_constraint :task_allowed_services, "service ~ '^[a-z0-9][a-z0-9_.-]{0,55}\\.service$'", name: "task_allowed_services_service_format"
    add_check_constraint :task_allowed_services, "tag IS NULL OR tag ~ '^[a-z0-9][a-z0-9_-]{0,31}$'", name: "task_allowed_services_tag_format"

    # CREATE OR REPLACE in place: fx's update_function drops the function first, which its triggers depend on.
    reversible do |direction|
      direction.up { execute Rails.root.join("db/functions/tasks_guard_v02.sql").read }
      direction.down { execute Rails.root.join("db/functions/tasks_guard_v01.sql").read }
    end
  end
end
