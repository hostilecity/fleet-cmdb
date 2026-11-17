# One verdict of vulnerability matching for a chunk (#196, ADR 0028, P2-S11): an advisory that affects one binary
# package of the chunk in one ecosystem, with the installed version and the fix of the range it is in. Exact for every
# host whose set has the chunk, since a package's verdict depends only on its own version and source. Written only by
# VulnerabilityMatcher::Chunks.
class ChunkMatch < ApplicationRecord
  self.primary_key = %i[package_chunk_id ecosystem advisory_id package architecture]

  belongs_to :package_chunk
  belongs_to :advisory

  def key = [ advisory_id, package, architecture ]
end
