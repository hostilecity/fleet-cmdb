# One installed package in a PackageChunk (#196, ADR 0028, P2-S08): name, architecture, full version, and source
# package (nil when it is its own source).
class PackageChunkEntry < ApplicationRecord
  self.primary_key = %i[package_chunk_id name architecture]

  belongs_to :package_chunk, inverse_of: :entries

  def to_package = AgentApi::PackageReport::Package.new(name:, architecture:, version:, source:)
end
