# A host's whole package set as it was when it changed (P2-S08, FR-2.3, DEC-07): created only when the
# content hash changes, retained per NFR-2 (the newest per host is always kept). packages holds
# [name, architecture, version, source] rows sorted by name and architecture.
class PackageSnapshot < ApplicationRecord
  belongs_to :host

  scope :chronological, -> { order(:received_at, :id) }

  def unsupported? = manager == "unsupported"
  def unreadable? = manager == "unreadable"

  def package_list = packages.map { |row| AgentApi::PackageReport::Package.from_a(row) }

  # The packages the report named but did not list as installed (P2-S08).
  def skipped_list = skipped.map { |row| AgentApi::PackageReport::Skipped.new(row["name"], row["reason"]) }

  # The host's snapshot before this one, or nil for its first.
  def previous = earlier.first

  # The last snapshot before this one that was not unreadable: an unreadable report says nothing changed, so the
  # set before it is still the one to compare with.
  def previous_known = earlier.where.not(manager: "unreadable").first

  private

  def earlier
    PackageSnapshot.where(host_id:).where("(received_at, id) < (?, ?)", received_at, id).order(received_at: :desc, id: :desc)
  end
end
