# The stable inventory fields as they were when they last changed (FR-1.3, DEC-07). Created only when the
# hash of the stable fields changes, so an operator can see what changed and when. Retained per NFR-2.
class InventorySnapshot < ApplicationRecord
  belongs_to :host

  scope :chronological, -> { order(:received_at, :id) }
end
