# A host's backports (#274, Ecosystems::BACKPORTS), for the notice on its Vulnerabilities tab: the packages whose
# version has its release's backports marker (trixie-backports' ~bpo13), whether the advisory data of the release they
# are built from (Debian:14) is here yet (Backports.data?), the sources of all of them that data names nothing for (so
# what affects only the backport's series cannot be found for them), and how many of the host's open findings only a
# keep_only verdict holds open. Reads only, and only on a host with a backport: one query for its backports (its
# set's chunks, then the primary key, the count in the same statement), then the sources, the data, and the kept count.
class HostBackports
  LIMIT = 20

  Package = Data.define(:name, :architecture, :version)

  attr_reader :ecosystem, :from, :packages, :count, :uncovered, :kept

  # ecosystem: the host's (its evaluation's); package_set_id: its package set (nil: none).
  def initialize(ecosystem, package_set_id, host_id: nil)
    @ecosystem = ecosystem
    @from = Ecosystems.backports_from(ecosystem)
    @packages = []
    @uncovered = []
    @count = 0
    @kept = 0
    load(package_set_id, host_id) if @from && package_set_id
  end

  def any? = count.positive?

  def more? = count > packages.size

  def from_name = Ecosystems.display_name(from)

  # Whether the release they are built from has complete data here; until then they are matched on the host
  # release's data alone, as before #274.
  def data? = @data

  private

  def load(package_set_id, host_id)
    entries = PackageChunkEntry.where(package_chunk_id: PackageSet.where(id: package_set_id).select(Arel.sql("unnest(chunk_ids)")))
                               .where(Ecosystems.backport_like_sql(ecosystem))
    rows = entries.order(:name, :architecture).limit(LIMIT).pluck(:name, :architecture, :version, Arel.sql("count(*) OVER ()"))
    return if rows.empty?

    @count = rows.first.last
    @packages = rows.map { |name, architecture, version, _| Package.new(name:, architecture:, version:) }
    @data = Backports.data?(ecosystem)
    @uncovered = uncovered_sources(entries) if @data
    @kept = VulnerabilityFinding.with_details.active.where(host_id:).where(kept: true).count if @data && host_id
  end

  # The advisory sources of every backport of the host (not only those listed) that Debian:14's data names nothing for:
  # a package counts as covered when either name it is matched under is named.
  def uncovered_sources(entries)
    pairs = entries.distinct.pluck(:name, :source, :version).map do |name, source, version|
      [ SignedSources.resolve(ecosystem, name, source, version).source, source || name ]
    end.uniq
    named = AdvisoryPackage.where(ecosystem: from, package: pairs.flatten.uniq).distinct.pluck(:package).to_set
    pairs.reject { |names| names.any? { |n| named.include?(n) } }.map(&:first).uniq.sort
  end
end
