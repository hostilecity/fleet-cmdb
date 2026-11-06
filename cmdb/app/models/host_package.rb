# One package installed on a host now (P2-S08, FR-2.3), normalised so vulnerability matching (P2-S11) can look
# packages up by source package. Replaced whenever the host's package set changes.
class HostPackage < ApplicationRecord
  belongs_to :host

  def to_package = AgentApi::PackageReport::Package.new(name:, architecture:, version:, source:)
end
