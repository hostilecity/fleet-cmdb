# The stable-field changes between two inventory snapshots, for the host history (FR-1.5, P1-D03). Each
# change has a label, the old value, and the new value (either may be nil: added, removed, or unreadable).
class InventoryDiff
  Change = Data.define(:label, :old, :new)

  SCALARS = {
    "hostname" => "Hostname", "kernel_version" => "Kernel", "architecture" => "Architecture", "cpu_model" => "CPU model",
    "cpu_cores" => "CPU cores", "memory_total_bytes" => "Total memory", "boot_id" => "Boot ID", "machine_id" => "Machine ID",
    "agent_version" => "Agent"
  }.freeze

  def self.between(previous, current) = new(previous, current).changes

  def initialize(previous, current)
    @old = previous || {}
    @new = current || {}
  end

  def changes
    list = []
    list << Change.new("Operating system", os_name(@old), os_name(@new)) if os_name(@old) != os_name(@new)
    SCALARS.each do |key, label|
      next if @old[key] == @new[key]

      list << (key == "memory_total_bytes" ? Change.new(label, ByteSize.format(@old[key]), ByteSize.format(@new[key])) : Change.new(label, @old[key], @new[key]))
    end
    list.concat(keyed_changes("disks", "mount", "Disk") { |d| d && "#{d['filesystem']}, #{ByteSize.format(d['size_bytes'])}" })
    list.concat(keyed_changes("network_interfaces", "name", "Interface") { |n| n && n["addresses"].join(", ") + (n["primary"] ? " (default route)" : "") })
    list
  end

  private

  # The name with its id and version, so a version_id change under the same pretty name still shows.
  def os_name(stable)
    os = stable["os"]
    return nil unless os

    detail = [ os["id"], os["version_id"] ].compact.join(" ")
    [ os["pretty_name"], ("(#{detail})" if detail.present?) ].compact.join(" ").presence
  end

  # Lists matched by key (mount point, interface name): added, removed, or changed entries.
  def keyed_changes(field, key, label)
    old_items = Array(@old[field]).index_by { |item| item[key] }
    new_items = Array(@new[field]).index_by { |item| item[key] }
    (old_items.keys | new_items.keys).sort.filter_map do |name|
      before, after = old_items[name], new_items[name]
      Change.new("#{label} #{name}", yield(before), yield(after)) if before != after
    end
  end
end
