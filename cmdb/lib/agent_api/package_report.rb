module AgentApi
  # Turns a schema-valid package report (docs/api packages.request) into the set to store, and applies the
  # check the schema cannot express (P2-S08, FR-2.3): a package name and architecture appear at most once
  # (dpkg's multi-arch allows libc6:amd64 beside libc6:i386, never two of either). Failures raise
  # ValidationFailed with a JSON Pointer per problem, before anything is written. The schema already limits
  # names, versions, and architectures to plain ASCII, so only warning messages need control characters removed.
  class PackageReport
    # One installed package. to_a is the compact form snapshots store.
    Package = Data.define(:name, :architecture, :version, :source) do
      def key = [ name, architecture ]
      def to_a = [ name, architecture, version, source ]
      def self.from_a(row) = new(*row)
    end

    WARNING_FIELDS = %w[field message].freeze

    # A package the agent saw but did not list as installed (an interrupted installation, or an entry it could not
    # carry whole): its name and why. The name covers every architecture.
    Skipped = Data.define(:name, :reason) do
      def to_h = { "name" => name, "reason" => reason }
    end

    attr_reader :report_id, :schema_version, :collected_at, :manager, :unsupported_reason, :packages, :skipped, :warnings, :in_use

    def initialize(payload)
      problems = duplicates(payload["packages"])
      raise ValidationFailed.new(details: problems) if problems.any?

      @report_id = payload["report_id"]
      @schema_version = payload["schema_version"]
      @collected_at = Time.iso8601(payload["collected_at"])
      @manager = payload["manager"]
      @unsupported_reason = payload["unsupported_reason"]&.gsub(InventoryReport::CONTROL_CHARACTERS, "")
      @packages = payload["packages"].map { |p| Package.new(*p.values_at("name", "architecture", "version", "source")) }.sort_by(&:key)
      @skipped = Array(payload["skipped"]).map { |s| Skipped.new(s["name"], s["reason"].gsub(InventoryReport::CONTROL_CHARACTERS, "")) }
                                          .sort_by { |s| [ s.name, s.reason ] }.uniq
      @warnings = payload["warnings"].map { |w| w.slice(*WARNING_FIELDS).transform_values { |v| v.gsub(InventoryReport::CONTROL_CHARACTERS, "") } }
                                     .sort_by { |w| [ w["field"], w["message"] ] }
      @in_use = build_in_use(payload["in_use"])
    end

    def unsupported? = manager == "unsupported"
    # dpkg is there but its packages could not be listed: the set is unknown, and the previous one is kept.
    def unreadable? = manager == "unreadable"

    # SHA-256 of the manager, its reason, the sorted packages, and the skipped names (only when there are any, so
    # a report without skipped packages hashes as it always did): the same set hashes the same whatever order the
    # agent listed it in, and a change of manager, reason, or skipped package is a change too.
    def content_hash
      parts = [ manager, unsupported_reason, packages.map(&:to_a) ]
      parts << skipped.map(&:to_h) if skipped.any?
      OpenSSL::Digest::SHA256.hexdigest(JSON.generate(parts))
    end

    private

    # FR-2.6 (#258): what is in use, as HostApplicability's columns, or nil when the report has none (absent or null;
    # the schema allows it only with dpkg). A package listed twice is network if either entry is, so the classes never
    # overlap. Not part of content_hash: a change of use is not a new package set.
    def build_in_use(in_use)
      return nil if in_use.nil?

      network = in_use["listening"].select { |l| l["class"] == "network" }.map { |l| l["package"] }.uniq.sort
      loopback = (in_use["listening"].map { |l| l["package"] }.uniq - network).sort
      libraries = Array(in_use["libraries"])
      {
        "in_use_reported" => true,
        "listening_network" => network,
        "listening_loopback" => loopback,
        "running_services" => in_use["services"].uniq.sort,
        "unnamed_network" => in_use["unnamed_listeners"]["network"],
        "unnamed_loopback" => in_use["unnamed_listeners"]["loopback"],
        "library_scan" => in_use["library_scan"],
        "libraries" => libraries.map { |l| l["package"] }.uniq.sort,
        "stale_libraries" => libraries.select { |l| l["stale"] }.map { |l| l["package"] }.uniq.sort
      }
    end

    def duplicates(packages)
      seen = Set.new
      packages.each_with_index.filter_map do |package, i|
        next if seen.add?(package.values_at("name", "architecture"))

        { "pointer" => "/packages/#{i}", "problem" => "duplicates an earlier package with the same name and architecture" }
      end
    end
  end
end
