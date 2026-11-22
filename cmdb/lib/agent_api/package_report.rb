require "ipaddr"

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
      problems = duplicates(payload["packages"]) + bad_sockets(payload["in_use"])
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
    # the schema allows it only with dpkg). The lists are positive evidence only (HostApplicability). A package listed
    # twice is network if either entry is, so the classes never overlap. Not part of content_hash: a change of use is
    # not a new package set.
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
        "stale_libraries" => libraries.select { |l| l["stale"] }.map { |l| l["package"] }.uniq.sort,
        # nil: the scan ran on a kernel that cannot tell (re-review of #268, N3), kept apart from [].
        "loaded_by_listeners" => in_use["library_scan"] == "ran" && in_use["loaded_by_listeners"].nil? ? nil : loaded_by_listeners(in_use["loaded_by_listeners"]),
        "library_scanned_at" => in_use["scanned_at"] && Time.iso8601(in_use["scanned_at"])
      }
    end

    # One entry per (listener, service), stored as the agent sends it (fifth review of #268, N6): a duplicate (a
    # hand-made report; the agent sends none) merges, with its packages joined and its sockets joined network first,
    # then by text, at most 4 (N2). It is network if any entry says so or any of its sockets is not on loopback, so a
    # hand-made "loopback" holding 0.0.0.0 cannot understate exposure (re-review, N2). Sorted (nil first), so equal
    # reports store equal values and write nothing.
    def loaded_by_listeners(uses)
      Array(uses).group_by { |use| use.values_at("listener", "service") }.map do |(listener, service), same|
        { "listener" => listener, "service" => service,
          "class" => same.any? { |use| use["class"] == "network" || use["sockets"].any? { |socket| !loopback?(socket) } } ? "network" : "loopback",
          "sockets" => same.flat_map { |use| use["sockets"] }.uniq.sort_by { |socket| [ loopback?(socket) ? 1 : 0, socket ] }.first(4),
          "packages" => same.flat_map { |use| use["packages"] }.uniq.sort }
      end.sort_by { |use| use.values_at("listener", "service").flat_map { |v| [ v.nil? ? 0 : 1, v.to_s ] } }
    end

    def loopback?(socket) = IPAddr.new(socket_address(socket)).then { |ip| ip.loopback? || (ip.ipv4_mapped? && ip.native.loopback?) }

    def socket_address(socket) = socket.rpartition(":").first.delete_prefix("[").delete_suffix("]")

    # The schema bounds each socket's text; an address IPAddr cannot read is refused too (fifth review, N4), and so is
    # an IPv6 address without brackets or an IPv4 one in them, as the agent writes neither (re-review, N6).
    def bad_sockets(in_use)
      Array(in_use && in_use["loaded_by_listeners"]).each_with_index.flat_map do |use, i|
        use["sockets"].each_with_index.filter_map do |socket, j|
          next if IPAddr.new(socket_address(socket)).ipv6? == socket.start_with?("[")

          { "pointer" => "/in_use/loaded_by_listeners/#{i}/sockets/#{j}", "problem" => "is not an address and port" }
        rescue IPAddr::InvalidAddressError
          { "pointer" => "/in_use/loaded_by_listeners/#{i}/sockets/#{j}", "problem" => "is not an address and port" }
        end
      end
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
