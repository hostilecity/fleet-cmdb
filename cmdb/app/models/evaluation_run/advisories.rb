class EvaluationRun
  # An advisory import (Advisories::Import, packages { "Debian:13" => ["openssl"] }): the hosts with a package built
  # from one of those sources, or a finding for one, matched for those packages only; and, in full, every host whose
  # last evaluation is missing or was "no advisory data", since the import may have brought its first data. Both
  # lookups use the source-package indexes (#185), so finding the hosts does not read every host's packages.
  class Advisories
    def initialize(scope)
      @packages = scope["packages"].to_h.transform_values { |sources| Array(sources) }
    end

    attr_reader :packages

    def hosts
      affected = supported.map do |ecosystem, sources|
        Host.in_fleet.where(id: HostPackage.where("COALESCE(source, name) IN (?)", sources).select(:host_id))
            .or(Host.in_fleet.where(id: VulnerabilityFinding.where(ecosystem:, source: sources).select(:host_id)))
      end
      affected.reduce(unevaluated) { |all, scope| all.or(scope) }
    end

    # Matches the range's affected hosts, as VulnerabilityMatchJob did for the whole fleet before #197; returns the
    # hosts whose shown vulnerabilities changed.
    def call(range)
      # Taken before the targeted run, which marks its hosts evaluated: a host never fully evaluated gets a full
      # run, not only the changed packages (review of #105).
      full = unevaluated.where(id: range).pluck(:id)
      targeted = supported.flat_map do |ecosystem, sources|
        HostPackage.where(host_id: range).where("COALESCE(source, name) IN (?)", sources).distinct.pluck(:host_id) |
          VulnerabilityFinding.where(host_id: range, ecosystem:, source: sources).distinct.pluck(:host_id)
      end.uniq - full
      changed = targeted.any? ? VulnerabilityMatcher.match!(targeted, packages:).changed_host_ids : []
      changed | VulnerabilityMatcher.match!(full).changed_host_ids
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

    def unevaluated
      evaluated = HostVulnerabilityEvaluation.where.not(reason: "no_advisory_data").or(HostVulnerabilityEvaluation.where(reason: nil)).select(:host_id)
      Host.in_fleet.where.not(id: evaluated)
    end
  end
end
