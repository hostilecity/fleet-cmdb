# What changed between two package sets (P2-S08, FR-2.3, AC-2.3): packages installed, removed, and changed,
# keyed by name and architecture. A change says whether it is an upgrade or a downgrade by dpkg's ordering
# (FR-2.4), :same when only the source package changed, or :invalid when either version cannot be compared.
#
#   PackageDiff.between(older_snapshot, newer_snapshot)
#   PackageDiff.for(snapshot) # against the host's snapshot before it; everything is installed for the first
class PackageDiff
  Change = Data.define(:name, :architecture, :from, :to, :direction)

  DIRECTIONS = { -1 => :upgrade, 0 => :same, 1 => :downgrade, invalid: :invalid }.freeze

  attr_reader :installed, :removed, :changed

  # older and newer are PackageSnapshots, or arrays of AgentApi::PackageReport::Package (nil for nothing).
  def self.between(older, newer, scheme: PackageVersions::Dpkg) = new(list(older), list(newer), scheme)

  def self.for(snapshot, scheme: PackageVersions::Dpkg) = between(snapshot.previous, snapshot, scheme:)

  def self.list(set) = set.respond_to?(:package_list) ? set.package_list : Array(set)
  private_class_method :list

  def initialize(older, newer, scheme)
    before = older.index_by(&:key)
    after = newer.index_by(&:key)
    @installed = after.except(*before.keys).values.sort_by(&:key)
    @removed = before.except(*after.keys).values.sort_by(&:key)
    @changed = after.slice(*before.keys).filter_map do |key, now|
      was = before.fetch(key)
      next if was == now

      Change.new(name: now.name, architecture: now.architecture, from: was, to: now,
                 direction: DIRECTIONS.fetch(scheme.compare(was.version, now.version)))
    end.sort_by { |c| [ c.name, c.architecture ] }
  end

  def empty? = installed.empty? && removed.empty? && changed.empty?
  def upgraded = changed.select { |c| c.direction == :upgrade }
  def downgraded = changed.select { |c| c.direction == :downgrade }
end
