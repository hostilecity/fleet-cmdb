# A host's backports (#274, Ecosystems::BACKPORTS), for the notice on its Vulnerabilities tab: the packages whose
# version has its release's backports marker (trixie-backports' ~bpo13), and whether the advisory data of the release
# they are built from (Debian:14) names each one's source. Those packages are matched against that release's
# advisories as well as their own, and their findings resolve as fixed only on its evidence; where it names nothing
# for a package, what affects only the backport's series cannot be found, and the notice says so. One query for the
# backports of the host's set (its chunks, then the primary key, with the count in the same statement), and one for
# the advisory sources when there are any. Reads only.
class HostBackports
  LIMIT = 20

  Package = Data.define(:name, :architecture, :version, :source, :covered)

  attr_reader :ecosystem, :from, :packages, :count

  # ecosystem: the host's (its evaluation's); package_set_id: its package set (nil: none).
  def initialize(ecosystem, package_set_id)
    @ecosystem = ecosystem
    @from = Ecosystems.backports_from(ecosystem)
    @packages = []
    @count = 0
    load(package_set_id) if @from && package_set_id
  end

  def any? = count.positive?

  # The backports listed whose source the other release's data names nothing for.
  def uncovered = packages.reject(&:covered)

  def more? = count > packages.size

  def from_name = Ecosystems.display_name(from)

  private

  def load(package_set_id)
    chunks = PackageSet.where(id: package_set_id).select(Arel.sql("unnest(chunk_ids)"))
    rows = PackageChunkEntry.where(package_chunk_id: chunks).where(Ecosystems.backport_like_sql(ecosystem)).order(:name, :architecture).limit(LIMIT)
                            .pluck(:name, :architecture, :version, :source, Arel.sql("count(*) OVER ()"))
    return if rows.empty?

    @count = rows.first.last
    sources = rows.to_h { |name, _, version, source, _| [ name, SignedSources.resolve(ecosystem, name, source, version).source ] }
    named = AdvisoryPackage.where(ecosystem: from, package: (sources.values + rows.map { |name, _, _, source, _| source || name }).uniq).distinct.pluck(:package).to_set
    @packages = rows.map do |name, architecture, version, source, _|
      Package.new(name:, architecture:, version:, source: sources[name], covered: named.include?(sources[name]) || named.include?(source || name))
    end
  end
end
