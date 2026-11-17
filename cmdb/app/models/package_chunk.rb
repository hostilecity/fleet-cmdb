# The entries of one package set whose source package (COALESCE(source, name)) falls in one of PackageStore::BUCKETS
# buckets, stored once whatever the number of sets and hosts that have it (#196, ADR 0028). Written and collected only
# by PackageStore; never changed once written but for last_used_at.
class PackageChunk < ApplicationRecord
  has_many :entries, class_name: "PackageChunkEntry", inverse_of: :package_chunk
end
