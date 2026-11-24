# A host's backports (#274, Ecosystems::BACKPORTS), for the notice on its Vulnerabilities tab: the packages whose
# version has its release's backports marker (trixie-backports' ~bpo13), whether the advisory data of the releases they
# can be built from (Debian:14, and Debian:15 after forky's release, #304) is here yet (Backports.statuses) and how fresh
# it is, the sources of all of them that data names nothing for (so what affects only the backport's series cannot be
# found for them), and how many of the host's open findings only a keep_only verdict holds open. Reads only, and only on a host with a backport: one query for its backports (its
# set's chunks, then the primary key, the count in the same statement), then the sources, the data, and the kept count.
class HostBackports
  LIMIT = 20

  Package = Data.define(:name, :architecture, :version)

  attr_reader :ecosystem, :from, :packages, :count, :uncovered, :kept, :statuses

  # ecosystem: the host's (its evaluation's); package_set_id: its package set (nil: none).
  def initialize(ecosystem, package_set_id, host_id: nil)
    @ecosystem = ecosystem
    @from = Ecosystems.backports_from(ecosystem)
    @packages = []
    @uncovered = {}
    @statuses = []
    @count = 0
    @kept = 0
    load(package_set_id, host_id) if @from && package_set_id
  end

  def any? = count.positive?

  def more? = count > packages.size

  # The releases they are matched against: those with complete data ("Debian 14 (forky)", or "Debian 14 (forky) or
  # Debian 15 (duke)"), or the one they are built from while none is complete.
  def from_name = (complete.any? ? complete.map(&:from) : [ from ]).map { |e| Ecosystems.display_name(e) }.join(" or ")

  # Whether a release they can be built from has complete data here (Backports.statuses); until then they are matched
  # on the host release's data alone, as before #274.
  def data? = complete.any?

  # The status of the release they are built from (Debian:14).
  def primary = statuses.first

  # The complete releases' statuses.
  def complete = statuses.select(&:complete)

  # The complete releases whose data is older than the freshness limit (#304).
  def stale = complete.select(&:stale)

  # A notice paragraph's id: the name for the release they are built from, with the release's after it for another
  # ("backports_stale_debian_15").
  def element_id(name, release) = release == from ? name : "#{name}_#{release.parameterize(separator: '_')}"

  # How many of the release's entries the newest full import keeping it skipped as malformed.
  def skipped_entries = primary&.skipped_entries.to_i

  private

  def load(package_set_id, host_id)
    entries = PackageChunkEntry.where(package_chunk_id: PackageSet.where(id: package_set_id).select(Arel.sql("unnest(chunk_ids)")))
                               .where(Ecosystems.backport_like_sql(ecosystem))
    rows = entries.order(:name, :architecture).limit(LIMIT).pluck(:name, :architecture, :version, Arel.sql("count(*) OVER ()"))
    return if rows.empty?

    @count = rows.first.last
    @packages = rows.map { |name, architecture, version, _| Package.new(name:, architecture:, version:) }
    @statuses = Backports.statuses(ecosystem)
    @uncovered = uncovered_sources(entries) if data?
    @kept = VulnerabilityFinding.with_details.active.where(host_id:).where(kept: true).count if data? && host_id
  end

  # { release => sources }: the advisory sources of every backport of the host (not only those listed) that each
  # complete release's data names nothing for, releases with none left out. A package counts as covered when either
  # name it is matched under is named.
  def uncovered_sources(entries)
    pairs = entries.distinct.pluck(:name, :source, :version).map do |name, source, version|
      [ SignedSources.resolve(ecosystem, name, source, version).source, source || name ]
    end.uniq
    releases = complete.map(&:from)
    named = AdvisoryPackage.where(ecosystem: releases, package: pairs.flatten.uniq).distinct.pluck(:ecosystem, :package).to_set
    releases.to_h { |release| [ release, pairs.reject { |names| names.any? { |n| named.include?([ release, n ]) } }.map(&:first).uniq.sort ] }
            .reject { |_, sources| sources.empty? }
  end
end
