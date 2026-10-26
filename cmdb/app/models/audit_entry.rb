# One row of the append-only audit log. Write with Audit.record only. Saved entries are read-only here,
# and a database trigger rejects UPDATE, DELETE, and TRUNCATE on the table (db/triggers).
class AuditEntry < ApplicationRecord
  ACTOR_TYPES = %w[operator host system].freeze

  validates :actor_type, inclusion: { in: ACTOR_TYPES }
  validates :action, inclusion: { in: Audit::Actions::ALL }

  scope :chronological, -> { order(:occurred_at, :id) }
  scope :for_target, ->(record) { where(target_type: record.class.name, target_id: record.id) }

  def readonly?
    persisted? || super
  end

  def delete
    raise ActiveRecord::ReadOnlyRecord, "audit entries cannot be deleted"
  end
end
