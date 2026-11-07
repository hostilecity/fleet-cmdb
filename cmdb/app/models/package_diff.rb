# What changed between two package sets (P2-S08, FR-2.3, AC-2.3), keyed by name and architecture. A change says
# whether it is an upgrade or a downgrade by dpkg's ordering (FR-2.4), :same when dpkg treats the two versions as
# equal, or :invalid when either version cannot be compared.
#
#   PackageDiff.between(older_snapshot, newer_snapshot)
#   PackageDiff.for(snapshot) # against the host's snapshot before it; everything is installed for the first
#
# A skipped name (a package the report names but does not list: an interrupted installation, or an entry the agent
# could not carry) covers every architecture of that name, and is counted as present, with an unknown version.
# Each list is sorted by name, then architecture:
#
# - installed: [Package], in the newer set and not the older one, whose name the older report did not skip.
# - completed: [Completed], in the newer set, not in the older one, and skipped by the older report: an installation
#   that was interrupted and has finished. reason is the older report's reason for skipping it.
# - removed: [Package], in the older set, not in the newer one, and not skipped by the newer report.
# - skipped: [Skip], in the older set, not in the newer one, and skipped by the newer report: not counted as removed.
# - removed_skipped: [SkippedRemoval], skipped by the older report and in neither the newer set nor its skipped
#   names: removed while it was skipped, so its version is not known (reason is the older report's).
# - changed: [Change], in both with another version or source.
# A name skipped by both reports is not a change.
#
# A set from an unsupported package manager is unknown, not empty (review of #98), and so is one the agent could
# not read: a diff with one on either side is not available (available? is false, with the reason) and lists
# nothing, so moving to or from one is never shown as every package removed or installed. PackageDiff.for passes
# over an unreadable snapshot before the one given, since it says nothing changed; when the only earlier snapshots
# kept are unreadable, the set before is unknown and the diff is not available (review of #121). The host's first
# snapshot (none before it) has everything installed.
class PackageDiff
  Change = Data.define(:name, :architecture, :from, :to, :direction)
  # A package that was installed and is not now, but is named in the newer report's skipped list.
  Skip = Data.define(:name, :architecture, :package, :reason)
  # A package installed now whose name the older report skipped (package is the newer one).
  Completed = Data.define(:name, :architecture, :package, :reason)
  # A name the older report skipped that the newer report neither lists nor skips. No architecture or version.
  SkippedRemoval = Data.define(:name, :reason)

  DIRECTIONS = { -1 => :upgrade, 0 => :same, 1 => :downgrade, invalid: :invalid }.freeze
  UNAVAILABLE = "the package manager was unsupported, so the package set is unknown"
  UNREADABLE = "the package database could not be read, so the package set is unknown"
  NO_KNOWN_BASELINE = "every earlier snapshot kept is one whose package database could not be read, so the package set before it is unknown"

  attr_reader :installed, :completed, :removed, :skipped, :removed_skipped, :changed, :unavailable_reason

  # older and newer are PackageSnapshots, or arrays of AgentApi::PackageReport::Package (nil for nothing).
  def self.between(older, newer, scheme: PackageVersions::Dpkg)
    reason = [ older, newer ].filter_map { |set| unknown_reason(set) }.first
    return new([], [], scheme, unavailable_reason: reason) if reason

    new(list(older), list(newer), scheme, older_skipped: skipped_list(older), skipped: skipped_list(newer))
  end

  def self.for(snapshot, scheme: PackageVersions::Dpkg)
    known = snapshot.previous_known
    return new([], [], scheme, unavailable_reason: NO_KNOWN_BASELINE) if known.nil? && snapshot.previous

    between(known, snapshot, scheme:)
  end

  def self.list(set) = set.respond_to?(:package_list) ? set.package_list : Array(set)
  def self.skipped_list(set) = set.respond_to?(:skipped_list) ? set.skipped_list : []
  private_class_method :list, :skipped_list

  def self.unknown_reason(set)
    return UNAVAILABLE if set.respond_to?(:unsupported?) && set.unsupported?

    UNREADABLE if set.respond_to?(:unreadable?) && set.unreadable?
  end
  private_class_method :unknown_reason

  def initialize(older, newer, scheme, unavailable_reason: nil, older_skipped: [], skipped: [])
    @unavailable_reason = unavailable_reason
    before = older.index_by(&:key)
    after = newer.index_by(&:key)
    was_skipped = reasons(older_skipped)
    now_skipped = reasons(skipped)
    new_here, @installed = after.except(*before.keys).values.sort_by(&:key).partition { |p| was_skipped.key?(p.name) }
    @completed = new_here.map { |p| Completed.new(name: p.name, architecture: p.architecture, package: p, reason: was_skipped[p.name]) }
    gone, @removed = before.except(*after.keys).values.sort_by(&:key).partition { |p| now_skipped.key?(p.name) }
    @skipped = gone.map { |p| Skip.new(name: p.name, architecture: p.architecture, package: p, reason: now_skipped[p.name]) }
    listed_now = newer.to_set(&:name)
    @removed_skipped = was_skipped.reject { |name, _| listed_now.include?(name) || now_skipped.key?(name) }
                                  .sort.map { |name, reason| SkippedRemoval.new(name:, reason:) }
    @changed = after.slice(*before.keys).filter_map do |key, now|
      was = before.fetch(key)
      next if was == now

      Change.new(name: now.name, architecture: now.architecture, from: was, to: now,
                 direction: DIRECTIONS.fetch(scheme.compare(was.version, now.version)))
    end.sort_by { |c| [ c.name, c.architecture ] }
  end

  def available? = unavailable_reason.nil?
  def empty? = [ installed, completed, removed, skipped, removed_skipped, changed ].all?(&:empty?)
  def upgraded = changed.select { |c| c.direction == :upgrade }
  def downgraded = changed.select { |c| c.direction == :downgrade }

  private

  # { name => the first reason given for it }.
  def reasons(skipped) = skipped.each_with_object({}) { |s, by_name| by_name[s.name] ||= s.reason }
end
