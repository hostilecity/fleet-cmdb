# What a server knows about backports beyond the static table (Ecosystems::BACKPORTS, #274, #304, ADR 0011).
#
# - complete(ecosystem): the releases the ecosystem's backports can be built from (Debian:14, and Debian:15 for
#   trixie-backports-sloppy after forky's release, #304) whose advisory data is complete here: a succeeded full import
#   kept it (its malformed entries are skipped and counted, never its records' Debian:13 data; status says how many).
#   Backports are matched against each of them, and data? is whether there is any. Until then backports are matched on
#   their own release's data alone, as before #274: a partial upload of a few Debian:14 records cannot tell an advisory
#   that does not name forky from one not imported, so no verdict rests on its absence. The first full import that
#   keeps one re-matches every stored backport (Advisories::Import).
# - statuses(ecosystem): one per release, for Data sources and the host tab: whether it is complete, how fresh, and
#   whether full imports have been arriving without it (#304, "never complete").
# - sources(ecosystem): the advisory sources the stored backports are matched as (SignedSources), for that re-match,
#   bin/rails vulnerabilities:rematch_backports, and EvaluationRun::Advisories.backports_scope.
module Backports
  module_function

  def data?(ecosystem) = complete(ecosystem).any?

  # In Ecosystems.backports_releases' order. One query.
  def complete(ecosystem)
    releases = Ecosystems.backports_releases(ecosystem)
    return [] if releases.empty?

    kept = AdvisoryImport.succeeded.where(full: true).where("ecosystems && ARRAY[?]::varchar[]", releases)
                         .from("advisory_imports, unnest(advisory_imports.ecosystems) AS kept").distinct.pluck(Arel.sql("kept"))
    releases & kept
  end

  # The releases of complete (Backports.complete) a backport of the ecosystem, at version, is matched against
  # (#304, owner decision of 2026-11-23 on PR #309): the one its backports are built from, and the sloppy one (Debian:15)
  # only when the version sorts above the first's version of the source (versions: { source => version } there,
  # BackportSourceVersion), since Debian refuses backports above it once it is released. sources: the names the package
  # is matched under, the one compared first (a signed image's linux, then linux-signed-amd64): the first with a known
  # version there is used. When none is known, or a version cannot be parsed, it is matched against both: that only adds
  # findings.
  def releases_for(ecosystem, complete, sources, version, versions, scheme)
    sloppy = sloppy_of(ecosystem)
    return complete unless sloppy && complete.include?(sloppy)

    known = Array(sources).filter_map { |source| versions[source] }.first
    left = known && scheme.parse(version)
    right = known && scheme.parse(known)
    return complete if known.nil? || [ left, right ].any?(PackageVersions::Invalid)

    scheme.compare(left, right).positive? ? complete : complete - [ sloppy ]
  end

  def sloppy_of(ecosystem) = Ecosystems::BACKPORTS.dig(ecosystem, "sloppy")

  # { source => version } in the release the ecosystem's backports are built from (Debian:14), for the sources, when
  # complete has its sloppy release (otherwise nothing reads it).
  def from_versions(ecosystem, complete, sources)
    sloppy = sloppy_of(ecosystem)
    sloppy && complete.include?(sloppy) ? BackportSourceVersion.of(Ecosystems.backports_from(ecosystem), sources) : {}
  end

  # The succeeded full imports that kept the ecosystem.
  def full_imports(from) = AdvisoryImport.succeeded.where(full: true).where("? = ANY (ecosystems)", from)

  # One release backports can be built from (from), in the ecosystem's order:
  # - sloppy: it is the one backports-sloppy builds are built from (Debian:15), which OSV has data for only after the
  #   other is released, so having none yet is expected; published: the security tracker names that release (it has
  #   versions of it, BackportSourceVersion), so it exists and an archive should have it (review of #309, N2);
  # - complete, and import: the newest full import that kept it, with the entries and records it found malformed;
  # - updated_at and stale: its freshness, as Advisories::Freshness has it for the fleet's ecosystems;
  # - missing: the newest succeeded full import, newer than import (or any when there is none), that did not keep it:
  #   the archive the server imports has no such data, so it never comes (or stopped coming) from there (#304). Its
  #   last known rows are kept then (Advisories::Import#held!), so backports are matched on them, going stale.
  Status = Data.define(:from, :sloppy, :published, :complete, :import, :skipped_entries, :malformed, :updated_at, :stale, :missing) do
    # :fresh; :dropped (complete, but the full imports since lack it: its last rows are kept); :stale; :missing (full
    # imports arrive without it, and it exists); :awaited (sloppy, not published yet); or :never.
    def state
      if complete then (missing ? :dropped : (stale ? :stale : :fresh))
      elsif sloppy && !(published && missing) then :awaited
      elsif missing then :missing
      else :never
      end
    end

    # Whether the tab and Data sources should warn: backports are matched on old or no data of this release.
    def warning? = %i[dropped stale missing never].include?(state)
  end

  def statuses(ecosystem, now: Time.current, max_age: Advisories.config.max_age)
    Ecosystems.backports_releases(ecosystem).map do |from|
      import = full_imports(from).order(finished_at: :desc, id: :desc).first
      missing = AdvisoryImport.succeeded.where(full: true).where.not("? = ANY (ecosystems)", from)
      missing = missing.where(AdvisoryImport.arel_table[:finished_at].gt(import.finished_at)) if import
      at = import&.finished_at
      sloppy = Ecosystems.sloppy?(from)
      Status.new(from:, sloppy:, published: sloppy && BackportSourceVersion.where(ecosystem: from).exists?, complete: !import.nil?, import:,
                 skipped_entries: import&.counts&.dig("skipped_by_ecosystem", from).to_i, malformed: import&.counts&.fetch("malformed", 0).to_i,
                 updated_at: at, stale: at.nil? || at < now - max_age, missing: missing.order(finished_at: :desc, id: :desc).first)
    end
  end

  # The release backports are built from (Debian:14), or nil when the ecosystem has no backports.
  def status(ecosystem, **) = statuses(ecosystem, **).first

  def sources(ecosystem)
    like = Ecosystems.backport_like_sql(ecosystem) or return []
    PackageChunkEntry.where(like).distinct.pluck(:name, :source).flat_map do |name, source|
      [ SignedSources.resolve(ecosystem, name, source, "").source, source || name ]
    end.uniq.sort
  end
end
