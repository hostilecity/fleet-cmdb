# What a host's last package report said (P2-S08, FR-2.3): the package manager, or that it is unsupported or
# unreadable and why, how many packages, the hash of the set, the packages skipped, and the report's warnings. The
# packages themselves are rows of HostPackage, and the set as it was whenever it changed is a PackageSnapshot.
# After an unreadable report the rows and the count are those of the last readable one.
class HostPackageSet < ApplicationRecord
  MANAGERS = %w[dpkg unsupported unreadable].freeze

  belongs_to :host

  validates :manager, inclusion: { in: MANAGERS }

  def unsupported? = manager == "unsupported"
  def unreadable? = manager == "unreadable"

  # The packages the last report named but did not list as installed (P2-S08).
  def skipped_list = skipped.map { |row| AgentApi::PackageReport::Skipped.new(row["name"], row["reason"]) }
end
