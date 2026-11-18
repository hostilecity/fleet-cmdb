# That a chunk is matched for an ecosystem (#196, ADR 0028 decision 7): against the advisory data as of
# advisory_import_id (the newest succeeded import when the match read it), with the package and advisory pairs whose
# versions dpkg could not parse. Written only by VulnerabilityMatcher::Chunks and EvaluationRun::Advisories.
class ChunkEvaluation < ApplicationRecord
  self.primary_key = %i[package_chunk_id ecosystem]

  belongs_to :package_chunk
end
