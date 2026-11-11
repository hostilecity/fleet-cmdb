# Task progress and results (FR-3.2, P3-S04).
#
# tasks gains the agent's progress (while running) and what identifies the result that ended it: its report id,
# a digest of what the agent sent (so a retry is recognised and a different result refused), when the server
# received it, and the structured details (for example reboot_required). The result's outcome, reason, exit
# status, agent times, and output already have columns (P3-S02).
#
# task_late_results holds a result that arrived after the server had ended the task itself (timed out, expired,
# lease expired, cancelled, or refused at claim): kept beside the task as an annotation, at most one per task,
# never changed or deleted. Terminal tasks never change (tasks_guard), so it cannot live on the task row.
#
# Details are bounded at 32 KiB as JSON: the largest that task-result.request allows (64 service names of 256
# characters, plus the other details) is about 17 KiB.
class AddTaskResults < ActiveRecord::Migration[8.1]
  OUTCOMES = %w[succeeded failed timed_out cancelled refused].freeze

  def change
    change_table :tasks, bulk: true do |t|
      t.integer :progress_percent
      t.datetime :progress_reported_at
      t.uuid :result_report_id
      t.string :result_digest, limit: 64
      t.datetime :result_received_at
      t.jsonb :result_details
    end
    add_check_constraint :tasks, "progress_percent BETWEEN 0 AND 100", name: "tasks_progress_percent"
    add_check_constraint :tasks, "result_details IS NULL OR jsonb_typeof(result_details) = 'object'", name: "tasks_result_details_object"
    add_check_constraint :tasks, "octet_length(result_details::text) <= 32768", name: "tasks_result_details_size"
    add_check_constraint :tasks, "(result_digest IS NULL) = (result_received_at IS NULL)", name: "tasks_result_received"

    create_table :task_late_results do |t|
      t.references :task, null: false, foreign_key: true, index: { unique: true }
      t.uuid :report_id, null: false
      t.string :outcome, limit: 16, null: false
      t.string :reason, limit: 32
      t.integer :exit_status
      t.datetime :agent_started_at
      t.datetime :agent_finished_at, null: false
      t.jsonb :details
      t.text :output
      t.boolean :output_truncated, null: false, default: false
      t.string :digest, limit: 64, null: false
      t.datetime :received_at, null: false
      t.datetime :created_at, null: false
    end
    add_check_constraint :task_late_results, "outcome IN (#{OUTCOMES.map { |o| "'#{o}'" }.join(', ')})", name: "task_late_results_outcome"
    add_check_constraint :task_late_results, "details IS NULL OR jsonb_typeof(details) = 'object'", name: "task_late_results_details_object"
    add_check_constraint :task_late_results, "octet_length(details::text) <= 32768", name: "task_late_results_details_size"
    add_check_constraint :task_late_results, "octet_length(output) <= 1048576", name: "task_late_results_output_size"

    create_function :task_late_results_guard
    create_trigger :task_late_results_immutable, on: :task_late_results
    create_trigger :task_late_results_no_truncate, on: :task_late_results
  end
end
