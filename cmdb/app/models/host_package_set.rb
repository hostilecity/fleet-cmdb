# What a host's last package report said (P2-S08, FR-2.3): the package manager, or that it is unsupported and
# why, how many packages, the hash of the set, and the report's warnings. The packages themselves are rows of
# HostPackage, and the set as it was whenever it changed is a PackageSnapshot.
class HostPackageSet < ApplicationRecord
  MANAGERS = %w[dpkg unsupported].freeze

  belongs_to :host

  validates :manager, inclusion: { in: MANAGERS }

  def unsupported? = manager == "unsupported"
end
