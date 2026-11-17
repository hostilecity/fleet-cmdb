# A host's package snapshots as the Packages tab and the comparison page show them (P2-D03, FR-2.3, review of #124).
#
#   timeline = PackageSnapshotTimeline.new(host_id)
#   timeline.entries  # the latest LIMIT snapshots, newest first, each with what changed since the one before it
#   timeline.pair(from: params[:from], to: params[:to]) # the two snapshots to compare, with their diff
#
# A snapshot row names its PackageSet (ADR 0028); the packages are read only for a diff. What changed between two
# snapshots is a PackageDiff::Summary, cached by the pair of set ids and the two snapshots' skipped names: sets never
# change once stored, and hosts in a template fleet share pairs, so one host's comparison warms the cache for the
# others. A set id is never reused while the cache can hold it (a set is collected only once unreferenced, and ids come
# from a sequence). Only pairs the cache misses read packages, and only the chunks that differ (PackageDiff). A pair
# with an unsupported or unreadable side has no diff and is not cached.
class PackageSnapshotTimeline
  LIMIT = 10
  # Every column but the warnings.
  COLUMNS = %i[id host_id manager unsupported_reason package_count content_hash package_set_id skipped report_id collected_at received_at].freeze
  CACHE_VERSION = 2

  # One row of the snapshot list. previous is the snapshot before it (for the comparison link), first that there is
  # none kept, and summary what changed since the last readable one before it (nil when none is listed).
  Entry = Data.define(:snapshot, :previous, :first, :summary)
  # Two snapshots to compare. reversed: from is the later one. pickable: [snapshot, latest?, oldest?] for every
  # snapshot kept, newest first.
  Pair = Data.define(:from, :to, :reversed, :pickable, :diff)

  attr_reader :host_id

  def initialize(host_id, cache: Rails.cache)
    @host_id = host_id
    @cache = cache
  end

  # The pair's sets and, when either names any, a digest of both snapshots' skipped names (the diff depends on them).
  def self.cache_key(older, newer)
    skipped = [ older.skipped, newer.skipped ]
    [ "package-diff-summary", CACHE_VERSION, older.package_set_id, newer.package_set_id,
      (OpenSSL::Digest::SHA256.hexdigest(JSON.generate(skipped)) if skipped.flatten.any?) ].compact
  end

  # The newest snapshot, or nil.
  def latest = rows.first

  # Whether there are more snapshots than entries lists.
  def more? = rows.size > LIMIT

  # The newest snapshot that is not unreadable, or nil.
  def last_readable = scope.where.not(manager: "unreadable").select(*COLUMNS).first

  def entries
    @entries ||= begin
      listed = rows.first(LIMIT)
      baselines = listed.each_index.to_h { |i| [ i, rows[(i + 1)..].find { |row| !row.unreadable? } ] } # an unreadable report says nothing changed (P2-S08)
      summaries = summaries_for(listed.each_index.filter_map { |i| [ baselines[i], listed[i] ] if baselines[i] })
      listed.each_with_index.map do |snapshot, i|
        Entry.new(snapshot:, previous: rows[i + 1], first: rows[i + 1].nil? && !more?,
                  summary: baselines[i] && summaries.fetch([ baselines[i].id, snapshot.id ]))
      end
    end
  end

  # How many snapshots are kept.
  def count = all.size

  # The pair to compare for ?from=&to= (snapshot ids as strings, either blank). By default the latest against the one
  # before it; with only to, to against the one before it, or, for the oldest kept, the oldest against the one after
  # it (review of #124). nil when fewer than two snapshots are kept. Raises ActiveRecord::RecordNotFound for an id
  # that is not one of this host's snapshots, even when there is nothing to compare.
  def pair(from: nil, to: nil)
    named = [ from, to ].select(&:present?)
    raise ActiveRecord::RecordNotFound, "no such package snapshot for this host" unless named.all? { |id| find(id) }
    return nil if all.size < 2

    to_row = to.present? ? find(to) : all.first
    from_row = from.present? ? find(from) : all[all.index(to_row) + 1]
    from_row, to_row = to_row, all[all.index(to_row) - 1] if from_row.nil? # to is the oldest kept: compare it with the next
    Pair.new(from: from_row, to: to_row, reversed: ([ from_row.received_at, from_row.id ] <=> [ to_row.received_at, to_row.id ]).positive?,
             pickable: all.map { |s| [ s, s == all.first, s == all.last ] }, diff: PackageDiff.between(from_row, to_row))
  end

  private

  def scope = PackageSnapshot.where(host_id:).order(received_at: :desc, id: :desc)

  # The latest LIMIT + 1 snapshots.
  def rows = @rows ||= scope.select(*COLUMNS).limit(LIMIT + 1).to_a

  # Every snapshot kept, for the pickers.
  def all = @all ||= scope.select(*COLUMNS).to_a

  def find(id) = all.find { |s| s.id.to_s == id.to_s }

  # { [older id, newer id] => PackageDiff::Summary } for the pairs, reading packages only for cache misses.
  def summaries_for(pairs)
    unknown, known = pairs.partition { |older, newer| [ older, newer ].any? { |row| row.unsupported? || row.unreadable? } }
    out = unknown.to_h { |older, newer| [ [ older.id, newer.id ], PackageDiff.between(older, newer).summary ] }
    keyed = known.group_by { |older, newer| self.class.cache_key(older, newer) }
    cached = keyed.any? ? @cache.read_multi(*keyed.keys) : {}
    keyed.each do |key, same|
      summary = cached[key] ? PackageDiff::Summary.from_h(cached[key]) : PackageDiff.between(*same.first).summary.tap { |s| @cache.write(key, s.to_h) }
      same.each { |older, newer| out[[ older.id, newer.id ]] = summary }
    end
    out
  end
end
