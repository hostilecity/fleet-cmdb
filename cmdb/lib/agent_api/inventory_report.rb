module AgentApi
  # Turns a schema-valid inventory report (docs/api inventory.request) into stable, volatile, and warning
  # data ready to store, and applies the checks the schema cannot express (P1-INVENTORY, FR-1.3, NFR-1):
  #
  # - control characters are stripped from every string (markup is kept and escaped when rendered);
  # - addresses must be valid CIDRs with a prefix that fits the address family;
  # - free space cannot exceed size, available memory cannot exceed total memory;
  # - mount points and interface names must be unique.
  #
  # Failures raise ValidationFailed with a JSON Pointer per problem, before anything is written.
  class InventoryReport
    STABLE_FIELDS = %w[hostname os kernel_version architecture cpu_model cpu_cores memory_total_bytes boot_id machine_id agent_version].freeze
    CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/

    attr_reader :report_id, :schema_version, :collected_at, :stable, :volatile, :warnings

    def initialize(payload)
      data = strip_control_characters(payload)
      problems = check(data)
      raise ValidationFailed.new(details: problems) if problems.any?

      @report_id = data["report_id"]
      @schema_version = data["schema_version"]
      @collected_at = Time.iso8601(data["collected_at"])
      @warnings = data["warnings"].sort_by { |w| [ w["field"], w["message"] ] }
      @stable = build_stable(data)
      @volatile = build_volatile(data)
    end

    # SHA-256 of the canonical stable fields: equal inventories hash equally whatever order the agent listed
    # disks, interfaces, or addresses in.
    def stable_hash = OpenSSL::Digest::SHA256.hexdigest(JSON.generate(canonical(stable)))

    def machine_id = stable["machine_id"]

    private

    def build_stable(data)
      fields = data.slice(*STABLE_FIELDS)
      fields["disks"] = data["disks"]&.map { |d| d.slice("mount", "filesystem", "size_bytes") }&.sort_by { |d| d["mount"] }
      fields["network_interfaces"] = data["network_interfaces"]&.map do |nic|
        { "name" => nic["name"], "primary" => nic["primary"], "addresses" => nic["addresses"].map { |a| normalize_address(a) }.uniq.sort }
      end&.sort_by { |nic| nic["name"] }
      fields
    end

    def build_volatile(data)
      {
        "memory_available_bytes" => data["memory_available_bytes"],
        "uptime_seconds" => data["uptime_seconds"],
        "disk_free_bytes" => data["disks"]&.to_h { |d| [ d["mount"], d["free_bytes"] ] }
      }
    end

    def check(data)
      problems = []
      total, available = data.values_at("memory_total_bytes", "memory_available_bytes")
      problems << problem("/memory_available_bytes", "exceeds memory_total_bytes") if total && available && available > total
      Array(data["disks"]).each_with_index do |disk, i|
        problems << problem("/disks/#{i}/free_bytes", "exceeds size_bytes") if disk["free_bytes"] > disk["size_bytes"]
      end
      problems.concat(duplicates(data["disks"], "mount", "/disks"))
      problems.concat(duplicates(data["network_interfaces"], "name", "/network_interfaces"))
      Array(data["network_interfaces"]).each_with_index do |nic, i|
        nic["addresses"].each_with_index do |address, j|
          problems << problem("/network_interfaces/#{i}/addresses/#{j}", "is not a valid IPv4 or IPv6 CIDR") unless normalize_address(address)
        end
      end
      problems
    end

    def duplicates(items, key, pointer)
      seen = {}
      Array(items).each_with_index.filter_map do |item, i|
        problem("#{pointer}/#{i}/#{key}", "duplicates an earlier entry") if seen.key?(item[key]).tap { seen[item[key]] = true }
      end
    end

    # "192.0.2.10/24" -> "192.0.2.10/24"; "2001:DB8::0010/64" -> "2001:db8::10/64"; invalid -> nil.
    def normalize_address(cidr)
      address, prefix = cidr.to_s.split("/", 2)
      ip = IPAddr.new(address)
      bits = Integer(prefix, 10)
      return nil unless bits.between?(0, ip.ipv4? ? 32 : 128)

      "#{ip}/#{bits}"
    rescue IPAddr::Error, ArgumentError, TypeError
      nil
    end

    def strip_control_characters(value)
      case value
      when Hash then value.to_h { |k, v| [ k, strip_control_characters(v) ] }
      when Array then value.map { |v| strip_control_characters(v) }
      when String then value.gsub(CONTROL_CHARACTERS, "")
      else value
      end
    end

    def canonical(value)
      case value
      when Hash then value.sort.to_h { |k, v| [ k, canonical(v) ] }
      when Array then value.map { |v| canonical(v) }
      else value
      end
    end

    def problem(pointer, text) = { "pointer" => pointer, "problem" => text }
  end
end
