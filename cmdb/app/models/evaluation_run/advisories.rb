class EvaluationRun
  # An advisory import (Advisories::Import; scope packages { "Debian:13" => ["openssl"] } and the import's id), matched
  # by chunk (#196, ADR 0028):
  #
  # - prepare! (once, as the run fans out, after the import committed): the chunks that hold a changed source are
  #   matched again, for each ecosystem they are evaluated in, and every other evaluation current with the import
  #   before this one is stamped with this one in one UPDATE, since nothing it matched changed (decision 7). Without
  #   that, every other chunk in use would look stale after each import and be matched again on its next use.
  # - hosts: those on a set holding a chunk with a changed source, and every host whose last evaluation is missing or
  #   was "no advisory data", since the import may have brought its first data. Their transitions run in full: they
  #   only read verdicts, and a host whose findings do not change writes nothing.
  #
  # The hosts are found from every chunk with a changed source, not only those whose verdicts changed: a host's own
  # report may match such a chunk again between the import and this run, and its change would then not be seen here.
  # A chunk matched against the data before the import (by a report in flight while it committed) is matched again
  # before any host uses it, by the transitions' check that every chunk is current with the newest import.
  class Advisories
    def initialize(scope)
      @packages = scope["packages"].to_h.transform_values { |sources| Array(sources) }
      @import_id = scope["import_id"]
    end

    attr_reader :packages

    def prepare!
      stamp = AdvisoryImport.newest_succeeded_id # before any advisory data is read
      changed = supported.to_h { |ecosystem, sources| [ ecosystem, changed_chunks(sources) ] }
      changed.each do |ecosystem, ids|
        VulnerabilityMatcher::Chunks.ensure!(ChunkEvaluation.where(ecosystem:, package_chunk_id: ids).pluck(:package_chunk_id), ecosystem, stamp:, force: true)
      end
      restamp(changed)
    end

    def hosts = Host.in_fleet.where(id: affected_hosts).or(unevaluated)

    # Matches the range's affected hosts; returns the hosts whose shown vulnerabilities changed.
    def call(range)
      ids = Host.in_fleet.where(id: range).merge(hosts).pluck(:id)
      VulnerabilityMatcher.match!(ids).changed_host_ids
    end

    # A later import of the same sources (or more) makes an older run redundant: it finds the same hosts, and
    # matches the newer advisories.
    def covers?(other)
      other.is_a?(Advisories) && other.packages.all? { |ecosystem, sources| (sources - packages.fetch(ecosystem, [])).empty? }
    end

    # An import that changed advisories can change severities with no finding changing state (P2-D05).
    def refresh_always? = packages.values.any?(&:present?)

    private

    def supported = packages.select { |ecosystem, sources| Ecosystems.supported?(ecosystem) && sources.any? }

    def changed_chunks(sources) = PackageChunkEntry.where("COALESCE(source, name) IN (?)", sources).distinct.pluck(:package_chunk_id)

    # host_package_sets rows on a set holding a chunk with a changed source (the source index, then the GIN index).
    def affected_hosts
      return HostPackageSet.none.select(:host_id) if supported.empty?

      HostPackageSet.where(package_set_id: PackageSet.holding_sources(supported.values.flatten.uniq)).select(:host_id)
    end

    # Moves the evaluations current with the import before this one, and holding no changed source, to this one.
    def restamp(changed)
      import = @import_id && AdvisoryImport.succeeded.find_by(id: @import_id)
      previous = import&.previous_succeeded_id
      return unless previous

      scope = ChunkEvaluation.where(advisory_import_id: previous)
      changed.each { |ecosystem, ids| scope = scope.where.not(ecosystem:, package_chunk_id: ids) if ids.any? }
      scope.update_all(advisory_import_id: import.id)
    end

    # Hosts with no evaluation that had advisory data: none at all, or "no advisory data". A correlated NOT EXISTS, an
    # anti-join on the evaluations' host_id index, so it stays cheap per batch and over the fleet whatever work_mem
    # is; NOT IN (subquery) falls back to scanning every evaluation for each host once its hash no longer fits
    # (review of #204).
    UNEVALUATED = <<~SQL.squish.freeze
      NOT EXISTS (SELECT 1 FROM host_vulnerability_evaluations evaluations
                  WHERE evaluations.host_id = hosts.id AND evaluations.reason IS DISTINCT FROM 'no_advisory_data')
    SQL

    def unevaluated = Host.in_fleet.where(UNEVALUATED)
  end
end
