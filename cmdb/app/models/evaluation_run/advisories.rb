class EvaluationRun
  # An advisory import (Advisories::Import; scope packages { "Debian:13" => ["openssl"] } and the import's id), matched
  # by chunk (#196, ADR 0028):
  #
  # - prepare! (once, as the run fans out, after the import committed): the chunks that hold a changed source are
  #   matched again, for each ecosystem they are evaluated in, and then every other evaluation is moved to the newest
  #   import if no import since its stamp changed one of its sources (VulnerabilityMatcher::Chunks.restamp!, decision
  #   7). Without that, every other chunk in use would look stale after each import and be matched again on its next
  #   use. The rule reads what each import changed (AdvisoryImport#changed_packages), so it holds when an earlier
  #   import's run was superseded and never prepared, or when two runs prepare out of order.
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
    end

    attr_reader :packages

    def prepare!
      stamp = AdvisoryImport.newest_succeeded_id # before any advisory data is read
      supported.each do |ecosystem, sources|
        evaluated = ChunkEvaluation.where(ecosystem:, package_chunk_id: changed_chunks(ecosystem, sources)).pluck(:package_chunk_id)
        VulnerabilityMatcher::Chunks.ensure!(evaluated, ecosystem, stamp:, force: true)
      end
      VulnerabilityMatcher::Chunks.restamp!(stamp)
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

    # With the signed-template sources built from them (SignedSources): a change to linux's advisories is one to
    # linux-signed-amd64's images.
    def changed_chunks(ecosystem, sources) = PackageChunkEntry.where("COALESCE(source, name) IN (?)", SignedSources.reported(sources, ecosystem)).select(:package_chunk_id)

    # host_package_sets rows on a set holding a chunk with a changed source (the source index, then the GIN index).
    def affected_hosts
      return HostPackageSet.none.select(:host_id) if supported.empty?

      HostPackageSet.where(package_set_id: PackageSet.holding_sources(supported.values.flatten.uniq)).select(:host_id)
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
