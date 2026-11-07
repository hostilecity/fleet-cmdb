# What vulnerability matching needs to know about a host before looking at its packages (P2-S11, DEC-01,
# DEC-11): its ecosystem, from the inventory's os, and whether it can be matched at all. Loaded for many hosts in
# a fixed number of queries.
class HostContext
  REASONS = {
    "no_inventory" => "The host has not reported its inventory, so its distribution is not known.",
    "unmapped_distribution" => "%s is not in the fleet profile (DEC-01), so no advisory data applies to it.",
    "no_package_report" => "The host has not reported its packages.",
    "unsupported_package_manager" => "The host's package manager is not supported: %s",
    "no_advisory_data" => "No advisory data has been imported for %s."
  }.freeze

  attr_reader :host_id, :ecosystem, :reason, :detail

  # The ecosystems some successful import had data for.
  def self.ecosystems_with_data
    AdvisoryImport.succeeded.from("advisory_imports, unnest(advisory_imports.ecosystems) AS ecosystem").distinct.pluck("ecosystem").to_set
  end

  # One HostContext per id, in id order.
  def self.load(ids, with_data: ecosystems_with_data)
    os = HostInventory.where(host_id: ids).pluck(:host_id, Arel.sql("stable -> 'os'")).to_h
    sets = HostPackageSet.where(host_id: ids).pluck(:host_id, :manager, :unsupported_reason).to_h { |id, *rest| [ id, rest ] }
    ids.map { |id| new(id, os.key?(id), os[id], sets[id], with_data) }
  end

  def initialize(host_id, inventoried, os, package_set, with_data)
    @host_id = host_id
    @ecosystem = Ecosystems.for_os(os)
    manager, unsupported_reason = package_set
    @reason, argument =
      if !inventoried then [ "no_inventory" ]
      elsif @ecosystem.nil? then [ "unmapped_distribution", os_name(os) ]
      elsif package_set.nil? then [ "no_package_report" ]
      elsif manager == "unsupported" then [ "unsupported_package_manager", unsupported_reason ]
      elsif !with_data.include?(@ecosystem) then [ "no_advisory_data", @ecosystem ]
      end
    @detail = @reason && format(REASONS.fetch(@reason), argument).truncate(512)
  end

  def evaluable? = reason.nil?

  private

  def os_name(os)
    return "An unknown distribution" unless os.is_a?(Hash)

    [ os["id"], os["version_id"] ].compact.join(" ").presence || "An unknown distribution"
  end
end
