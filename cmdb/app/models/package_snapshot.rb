# A host's whole package set as it was when it changed (P2-S08, FR-2.3, DEC-07): created only when the
# content hash changes, retained per NFR-2 (the newest per host is always kept). packages holds
# [name, architecture, version, source] rows sorted by name and architecture.
class PackageSnapshot < ApplicationRecord
  belongs_to :host

  scope :chronological, -> { order(:received_at, :id) }

  def unsupported? = manager == "unsupported"

  def package_list = packages.map { |row| AgentApi::PackageReport::Package.from_a(row) }

  # The host's snapshot before this one, or nil for its first.
  def previous
    PackageSnapshot.where(host_id:).where("(received_at, id) < (?, ?)", received_at, id).order(received_at: :desc, id: :desc).first
  end
end
