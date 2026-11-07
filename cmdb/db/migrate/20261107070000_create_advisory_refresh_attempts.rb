# When each advisory feed refresh started (P2-REFRESH-LIMIT, P2-S15, FR-2.4): the scheduled job, the rake task,
# or an operator's "Refresh now". A manual refresh is refused while the newest attempt of any kind is younger
# than the cool-down (FLEET_ADVISORY_REFRESH_COOLDOWN). Advisories::ManualRefresh writes and reads these rows
# under a transaction-scoped advisory lock, so two operators clicking together start one refresh.
#
# A row is when a refresh started, not how it ended: the import it led to is in advisory_imports, and the audit
# log keeps who asked. Retention prunes rows past the retention window.
class CreateAdvisoryRefreshAttempts < ActiveRecord::Migration[8.1]
  def change
    create_table :advisory_refresh_attempts do |t|
      t.string :kind, null: false, limit: 16
      t.references :operator, foreign_key: true
      t.datetime :started_at, null: false # server clock
    end
    add_index :advisory_refresh_attempts, :started_at
    add_check_constraint :advisory_refresh_attempts, "kind IN ('manual', 'scheduled', 'task')", name: "advisory_refresh_attempts_kind_valid"
    add_check_constraint :advisory_refresh_attempts, "(kind = 'manual') = (operator_id IS NOT NULL)", name: "advisory_refresh_attempts_operator_iff_manual"
  end
end
