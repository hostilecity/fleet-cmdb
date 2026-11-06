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

    attr_reader :report_id, :schema_version, :collected_at, :manager, :unsupported_reason, :packages, :warnings

    def initialize(payload)
      problems = duplicates(payload["packages"])
      raise ValidationFailed.new(details: problems) if problems.any?

      @report_id = payload["report_id"]
      @schema_version = payload["schema_version"]
      @collected_at = Time.iso8601(payload["collected_at"])
      @manager = payload["manager"]
      @unsupported_reason = payload["unsupported_reason"]&.gsub(InventoryReport::CONTROL_CHARACTERS, "")
      @packages = payload["packages"].map { |p| Package.new(*p.values_at("name", "architecture", "version", "source")) }.sort_by(&:key)
      @warnings = payload["warnings"].map { |w| w.slice(*WARNING_FIELDS).transform_values { |v| v.gsub(InventoryReport::CONTROL_CHARACTERS, "") } }
                                     .sort_by { |w| [ w["field"], w["message"] ] }
    end

    def unsupported? = manager == "unsupported"

    # SHA-256 of the manager, its reason, and the sorted packages: the same set hashes the same whatever order
    # the agent listed it in, and a change of manager or reason is a change too.
    def content_hash = OpenSSL::Digest::SHA256.hexdigest(JSON.generate([ manager, unsupported_reason, packages.map(&:to_a) ]))

    private

    def duplicates(packages)
      seen = Set.new
      packages.each_with_index.filter_map do |package, i|
        next if seen.add?(package.values_at("name", "architecture"))

        { "pointer" => "/packages/#{i}", "problem" => "duplicates an earlier package with the same name and architecture" }
      end
    end
  end
end
