# A host's config facts as they were when they changed (P2-S02, FR-2.1, DEC-07): created only when the content
# hash changes, retained per NFR-2 (the newest per host is always kept). facts is
# { key => { "state", "value", "reason" } } for every fact in the manifest the server had then.
class ConfigSnapshot < ApplicationRecord
  belongs_to :host

  scope :chronological, -> { order(:received_at, :id) }

  # The host's snapshot before this one, or nil for its first.
  def previous
    ConfigSnapshot.where(host_id:).where("(received_at, id) < (?, ?)", received_at, id).order(received_at: :desc, id: :desc).first
  end
end
