# What changed between two sets of config facts of one host (P2-S02, FR-2.1, AC-2.1): facts added and removed
# (a manifest that gained a fact, or a server whose manifest was older), and facts changed, which includes a
# change of state alone (ok to unreadable, or unreadable with another reason).
#
#   ConfigDiff.between(older_snapshot, newer_snapshot)
#   ConfigDiff.for(snapshot) # against the host's snapshot before it; every fact is added for the first
class ConfigDiff
  Change = Data.define(:key, :from, :to) do
    def state_changed? = from["state"] != to["state"]
    def value_changed? = from["value"] != to["value"]
  end

  attr_reader :added, :removed, :changed

  # older and newer are ConfigSnapshots (or HostConfigs), or facts hashes; nil for nothing.
  def self.between(older, newer) = new(facts(older), facts(newer))

  def self.for(snapshot) = between(snapshot.previous, snapshot)

  def self.facts(set) = set.respond_to?(:facts) ? set.facts : set.to_h
  private_class_method :facts

  # added and removed are { key => fact }, sorted by key; changed is a list of Change, sorted by key.
  def initialize(before, after)
    @added = after.except(*before.keys).sort.to_h
    @removed = before.except(*after.keys).sort.to_h
    @changed = after.slice(*before.keys).filter_map { |key, now| Change.new(key:, from: before.fetch(key), to: now) unless before.fetch(key) == now }.sort_by(&:key)
  end

  def empty? = added.empty? && removed.empty? && changed.empty?
end
