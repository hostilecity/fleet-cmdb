# One liveness transition for a host (FR-1.4, P1-S09). Kept apart from the audit log because it is
# high-volume, derived data; retention is handled with the other history tables (NFR-2).
class HostStatusEvent < ApplicationRecord
  # Partitioned by time (ADR 0027): the table's key is (id, stored_at), ids still come from one sequence.
  self.primary_key = :id

  REASONS = %w[heartbeat evaluation].freeze

  belongs_to :host

  scope :chronological, -> { order(:occurred_at, :id) }
end
