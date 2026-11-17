# Stores each distinct package set once, in content-addressed chunks (#196, ADR 0028, P2-S08, NFR-3).
#
# - A chunk is the packages of a set whose source package, COALESCE(source, name), falls in one of BUCKETS buckets:
#   the first two bytes of the SHA-256 of that name, mod 64. A bucket depends only on the package's own source, so a
#   change copies only the chunks of the sources it touches (two for a package whose source changes), and chunk
#   boundaries never shift. Its hash is the SHA-256 of CHUNKING_VERSION, the bucket, and its entries sorted by name and
#   architecture. The bucket function is fixed for good; changing it means a new CHUNKING_VERSION and a rebuild.
# - A set is its chunk ids by bucket (PackageSet#chunk_ids, nil for an empty bucket). Its hash is the SHA-256 of its
#   chunk hashes in bucket order. Each distinct chunk and set is stored once.
# - store! finds or stores a list's chunks and set and returns the set's id. It runs in the caller's transaction (the
#   package report's, under the host lock); two reports storing the same new chunk or set at once both end with the
#   one row (INSERT ... ON CONFLICT DO NOTHING, then read).
# - Garbage collection is mark and sweep (collect!, after each retention run; decision 8): a set is kept while a host
#   or a snapshot references it, a chunk while a set holds it. There are no foreign keys from hosts, snapshots, or
#   sets, so instead store! touches a set or chunk it reuses when its last_used_at is more than TOUCH_AFTER old, and
#   collect! deletes only rows unreferenced and untouched for COLLECT_AFTER, re-checking last_used_at in the DELETE
#   itself. A touch and a delete then conflict on the row: if the touch wins, the delete skips the touched row; if
#   the delete wins, the touch finds nothing and store! stores the chunk or set again by its hash.
module PackageStore
  BUCKETS = 64
  CHUNKING_VERSION = 1
  TOUCH_AFTER = 1.day
  COLLECT_AFTER = 2.days
  INSERT_BATCH = 5_000
  COLLECT_BATCH = 1_000

  Package = AgentApi::PackageReport::Package
  Chunk = Data.define(:bucket, :packages, :content_hash)

  module_function

  def bucket(source_name) = OpenSSL::Digest::SHA256.digest(source_name).unpack1("n") % BUCKETS

  # The list's chunks in bucket order, each with its packages sorted by name and architecture.
  def chunks(packages)
    packages.sort_by(&:key).group_by { |p| bucket(p.source || p.name) }.sort.map do |bucket, list|
      Chunk.new(bucket:, packages: list, content_hash: OpenSSL::Digest::SHA256.digest(JSON.generate([ CHUNKING_VERSION, bucket, list.map(&:to_a) ])))
    end
  end

  def set_hash(chunks) = OpenSSL::Digest::SHA256.digest(chunks.map(&:content_hash).join)

  # The id of the PackageSet holding packages (AgentApi::PackageReport::Package), storing what is new.
  def store!(packages, now: Time.current)
    chunks = chunks(packages)
    hash = set_hash(chunks)
    id, last_used_at = PackageSet.where(content_hash: hash).pick(:id, :last_used_at)
    return id if id && (last_used_at > now - TOUCH_AFTER || touch!(PackageSet, [ id ], now).any?)

    by_bucket = chunk_ids(chunks, now)
    row = { content_hash: hash, chunk_ids: Array.new(BUCKETS) { |b| by_bucket[b] }, package_count: packages.size, created_at: now, last_used_at: now }
    PackageSet.insert_all([ row ], unique_by: :content_hash, returning: :id).rows.dig(0, 0) || PackageSet.where(content_hash: hash).pick(:id)
  end

  # The packages of a set, sorted by name and architecture ([] for nil).
  def packages(set_id) = entries(chunk_ids_of(set_id)).map(&:to_package)

  # { set id => [chunk ids, nil for an empty bucket] }.
  def chunk_ids_by_set(set_ids) = PackageSet.where(id: set_ids.compact.uniq).pluck(:id, :chunk_ids).to_h

  def chunk_ids_of(set_id) = set_id ? Array(chunk_ids_by_set([ set_id ])[set_id]).compact : []

  def entries(chunk_ids, names: nil)
    scope = PackageChunkEntry.where(package_chunk_id: chunk_ids)
    scope = scope.where(name: names) if names
    scope.order(:name, :architecture).to_a
  end

  # The packages of two sets in the buckets where they differ only (PackageDiff): [older, newer]. Equal buckets hold
  # the same chunk, so a diff of the rest is the diff of the whole sets.
  def differing_packages(older_set_id, newer_set_id)
    by_set = chunk_ids_by_set([ older_set_id, newer_set_id ])
    older, newer = by_set.values_at(older_set_id, newer_set_id).map { |ids| Array(ids || Array.new(BUCKETS)) }
    differ = (0...BUCKETS).reject { |b| older[b] == newer[b] }
    [ older, newer ].map { |ids| entries(differ.filter_map { |b| ids[b] }).map(&:to_package) }
  end

  # Which of names a set lists, in any bucket.
  def listed_names(set_id, names)
    return Set.new if names.empty?

    PackageChunkEntry.where(package_chunk_id: chunk_ids_of(set_id), name: names).distinct.pluck(:name).to_set
  end

  # Deletes (or, in a dry run, counts) the sets no host or snapshot references and the chunks no set holds, untouched
  # for COLLECT_AFTER, in short batches. Returns { "package_sets" => n, "package_chunks" => n }.
  def collect!(now: Time.current, dry_run: false, batch_size: COLLECT_BATCH)
    cutoff = now - COLLECT_AFTER
    counts = { "package_sets" => sweep(PackageSet, UNREFERENCED_SET, cutoff, dry_run, batch_size) }
    counts["package_chunks"] = sweep(PackageChunk, UNREFERENCED_CHUNK, cutoff, dry_run, batch_size)
    Rails.logger.info("[package store] #{dry_run ? 'dry run, would collect' : 'collected'} " \
                      "#{counts.map { |table, count| "#{table}=#{count}" }.join(' ')} unreferenced since #{cutoff.utc.iso8601}")
    counts
  end

  # What is wrong with the store's references, one line each (bin/rails packages:check_snapshots): with no foreign
  # keys, a bug could leave a dpkg snapshot or host with no set, or an id naming a set or chunk that is not stored.
  def check
    checks = {
      "dpkg package snapshots with no package set" => PackageSnapshot.where(manager: "dpkg", package_set_id: nil),
      "dpkg hosts with no package set" => HostPackageSet.where(manager: "dpkg", package_set_id: nil),
      "package snapshots naming a set that is not stored" => PackageSnapshot.where.not(package_set_id: nil).where.not(package_set_id: PackageSet.select(:id)),
      "hosts naming a package set that is not stored" => HostPackageSet.where.not(package_set_id: nil).where.not(package_set_id: PackageSet.select(:id)),
      "package sets naming a chunk that is not stored" =>
        PackageSet.where("EXISTS (SELECT 1 FROM unnest(chunk_ids) c(id) WHERE c.id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM package_chunks p WHERE p.id = c.id))")
    }
    checks.filter_map { |what, scope| (count = scope.count).positive? ? "#{count} #{what}" : nil }
  end

  UNREFERENCED_SET = <<~SQL.squish.freeze
    NOT EXISTS (SELECT 1 FROM host_package_sets h WHERE h.package_set_id = package_sets.id)
    AND NOT EXISTS (SELECT 1 FROM package_snapshots s WHERE s.package_set_id = package_sets.id)
  SQL
  UNREFERENCED_CHUNK = "NOT EXISTS (SELECT 1 FROM package_sets s WHERE s.chunk_ids @> ARRAY[package_chunks.id])".freeze

  # Rows of model unreferenced and untouched since cutoff, deleted in keyset batches by id. The DELETE checks
  # last_used_at again on each row it deletes, so a row store! touched meanwhile is skipped (decision 8).
  def sweep(model, unreferenced, cutoff, dry_run, batch_size)
    candidates = model.where(last_used_at: ...cutoff).where(unreferenced)
    return candidates.count if dry_run

    total = 0
    after = 0
    loop do
      ids = candidates.where(id: (after + 1)..).order(:id).limit(batch_size).pluck(:id)
      break if ids.empty?

      total += model.where(id: ids, last_used_at: ...cutoff).where(unreferenced).delete_all
      after = ids.last
    end
    total
  end

  # Moves last_used_at forward on rows still there; returns their ids (a row collected meanwhile is not among them).
  def touch!(model, ids, now)
    return [] if ids.empty?

    model.connection.select_values(model.sanitize_sql_array([ "UPDATE #{model.quoted_table_name} SET last_used_at = ? WHERE id IN (?) RETURNING id", now, ids ]))
  end

  # { bucket => chunk id } for the chunks, storing those not stored yet and touching old ones that are reused.
  def chunk_ids(chunks, now)
    found = PackageChunk.where(content_hash: chunks.map(&:content_hash)).pluck(:content_hash, :id, :last_used_at)
    stale = found.select { |_, _, used| used <= now - TOUCH_AFTER }.map { |_, id, _| id }
    kept = touch!(PackageChunk, stale, now).to_set
    ids = found.to_h { |hash, id, _| [ hash, id ] }.reject { |_, id| stale.include?(id) && !kept.include?(id) }
    missing = chunks.reject { |c| ids.key?(c.content_hash) }
    ids.merge!(insert_chunks(missing, now)) if missing.any?
    chunks.to_h { |c| [ c.bucket, ids.fetch(c.content_hash) ] }
  end

  # Stores new chunks and their entries; a chunk another report stored meanwhile is read instead (its entries are its).
  def insert_chunks(chunks, now)
    rows = chunks.map { |c| { bucket: c.bucket, content_hash: c.content_hash, package_count: c.packages.size, created_at: now, last_used_at: now } }
    # RETURNING gives bytea in its text form, which pluck would have decoded.
    inserted = PackageChunk.insert_all(rows, unique_by: :content_hash, returning: %i[content_hash id]).rows
                           .to_h { |hash, id| [ PG::Connection.unescape_bytea(hash), id ] }
    entries = chunks.select { |c| inserted.key?(c.content_hash) }.flat_map do |c|
      c.packages.map { |p| { package_chunk_id: inserted[c.content_hash], name: p.name, architecture: p.architecture, version: p.version, source: p.source } }
    end
    entries.each_slice(INSERT_BATCH) { |slice| PackageChunkEntry.insert_all(slice) }
    others = chunks.map(&:content_hash) - inserted.keys
    inserted.merge(others.any? ? PackageChunk.where(content_hash: others).pluck(:content_hash, :id).to_h : {})
  end

  private_class_method :sweep, :touch!, :chunk_ids, :insert_chunks
end
