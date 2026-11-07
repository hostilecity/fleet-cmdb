# What changed between two package sets (P2-S08, FR-2.3, AC-2.3): packages installed, removed, skipped, and
# changed, keyed by name and architecture. A change says whether it is an upgrade or a downgrade by dpkg's
# ordering (FR-2.4), :same when dpkg treats the two versions as equal, or :invalid when either version cannot be
# compared.
#
#   PackageDiff.between(older_snapshot, newer_snapshot)
#   PackageDiff.for(snapshot) # against the host's snapshot before it; everything is installed for the first
#
# A package in the older set that is not in the newer one is removed, unless the newer report names it as skipped
# (an interrupted installation, or an entry the agent could not carry): then it is skipped, with the reason, and
# not counted as removed. The name covers every architecture of it.
#
# A set from an unsupported package manager is unknown, not empty (review of #98), and so is one the agent could
# not read: a diff with one on either side is not available (available? is false, with the reason) and lists
# nothing, so moving to or from one is never shown as every package removed or installed. PackageDiff.for passes
# over an unreadable snapshot before the one given, since it says nothing changed.
class PackageDiff
  Change = Data.define(:name, :architecture, :from, :to, :direction)
  # A package that was installed and is not now, but is named in the newer report's skipped list.
  Skip = Data.define(:name, :architecture, :package, :reason)

  DIRECTIONS = { -1 => :upgrade, 0 => :same, 1 => :downgrade, invalid: :invalid }.freeze
  UNAVAILABLE = "the package manager was unsupported, so the package set is unknown"
  UNREADABLE = "the package database could not be read, so the package set is unknown"

  attr_reader :installed, :removed, :skipped, :changed, :unavailable_reason

  # older and newer are PackageSnapshots, or arrays of AgentApi::PackageReport::Package (nil for nothing).
  def self.between(older, newer, scheme: PackageVersions::Dpkg)
    reason = [ older, newer ].filter_map { |set| unknown_reason(set) }.first
    return new([], [], scheme, unavailable_reason: reason) if reason

    new(list(older), list(newer), scheme, skipped: newer.respond_to?(:skipped_list) ? newer.skipped_list : [])
  end

  def self.for(snapshot, scheme: PackageVersions::Dpkg) = between(snapshot.previous_known, snapshot, scheme:)

  def self.list(set) = set.respond_to?(:package_list) ? set.package_list : Array(set)
  private_class_method :list

  def self.unknown_reason(set)
    return UNAVAILABLE if set.respond_to?(:unsupported?) && set.unsupported?

    UNREADABLE if set.respond_to?(:unreadable?) && set.unreadable?
  end
  private_class_method :unknown_reason

  def initialize(older, newer, scheme, unavailable_reason: nil, skipped: [])
    @unavailable_reason = unavailable_reason
    before = older.index_by(&:key)
    after = newer.index_by(&:key)
    @installed = after.except(*before.keys).values.sort_by(&:key)
    gone = before.except(*after.keys).values.sort_by(&:key)
    reasons = skipped.each_with_object({}) { |s, by_name| by_name[s.name] ||= s.reason }
    @skipped = gone.select { |p| reasons.key?(p.name) }.map { |p| Skip.new(name: p.name, architecture: p.architecture, package: p, reason: reasons[p.name]) }
    @removed = gone.reject { |p| reasons.key?(p.name) }
    @changed = after.slice(*before.keys).filter_map do |key, now|
      was = before.fetch(key)
      next if was == now

      Change.new(name: now.name, architecture: now.architecture, from: was, to: now,
                 direction: DIRECTIONS.fetch(scheme.compare(was.version, now.version)))
    end.sort_by { |c| [ c.name, c.architecture ] }
  end

  def available? = unavailable_reason.nil?
  def empty? = installed.empty? && removed.empty? && skipped.empty? && changed.empty?
  def upgraded = changed.select { |c| c.direction == :upgrade }
  def downgraded = changed.select { |c| c.direction == :downgrade }
end
