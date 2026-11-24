# One distinct package set (#196, ADR 0028, P2-S08): its chunk ids by bucket (nil for an empty bucket), stored once
# whatever the number of hosts and snapshots that have it. Hosts (HostPackageSet) and snapshots (PackageSnapshot)
# point at it without a foreign key; PackageStore writes it, reads it, and collects it.
class PackageSet < ApplicationRecord
  # The sets holding a package built from one of sources (an advisory's source names), signed-template sources built
  # from them included (SignedSources, #270): the chunks from the entries' source index, then the sets from the GIN
  # index on chunk_ids.
  scope :holding_sources, lambda { |sources|
    holding_chunks(PackageChunkEntry.where("COALESCE(source, name) IN (?)", SignedSources.reported(sources)).select(:package_chunk_id))
  }

  # The sets holding one of the chunks a relation selects (package_chunk_id), from the GIN index on chunk_ids.
  scope :holding_chunks, ->(chunks) { where("chunk_ids && ARRAY(#{chunks.to_sql})::bigint[]").select(:id) }
end
