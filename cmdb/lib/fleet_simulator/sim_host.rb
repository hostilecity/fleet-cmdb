require "digest"

module FleetSimulator
  # One simulated host: its identity, its credential, its schedule, and how it misbehaves.
  #
  # Behaviours (assigned by .build_all from the end of the list, so sim-001 is always well behaved):
  #   stop        goes silent at silent_at: no heartbeats and no reports until resumed
  #   hostile     reports markup and invisible Unicode in its free-text fields (it must render escaped)
  #   churn       changes a stable field (the kernel version) in every report, so snapshots accumulate
  #   duplicates  resends every report with the same report id (the server must answer duplicate: true)
  class SimHost
    BEHAVIOURS = %i[stop hostile churn duplicates].freeze

    attr_reader :index, :name, :hostname, :machine_id, :boot_id, :started_at, :behaviour
    attr_accessor :credential, :host_id, :last_heartbeat_at, :heartbeat_interval, :inventory_interval, :next_heartbeat_at,
                  :next_inventory_at, :silent_at, :generation, :busy

    # counts: { stop: 1, hostile: 2, ... }.
    def self.build_all(count, counts: {}, now: Time.current)
      queue = BEHAVIOURS.flat_map { |behaviour| [ behaviour ] * counts.fetch(behaviour, 0) }
      offset = count - queue.size
      (1..count).map { |index| new(index:, behaviour: index > offset ? queue[index - offset - 1] : nil, now:) }
    end

    def initialize(index:, behaviour: nil, now: Time.current)
      @index = index
      @name = format("%s%03d", NAME_PREFIX, index)
      @hostname = "#{@name}.example.lan"
      # Stable per name, so a rerun reports the same machine and is not flagged as a clone (FR-S.1).
      @machine_id = Digest::SHA256.hexdigest("fleet-simulator #{@name}")[0, 32]
      @boot_id = SecureRandom.uuid
      @started_at = now
      @behaviour = behaviour
      @generation = 0
      @busy = false
    end

    def silent?(now) = !silent_at.nil? && now >= silent_at

    def resume! = self.silent_at = nil

    BEHAVIOURS.each { |behaviour| define_method(:"#{behaviour}?") { @behaviour == behaviour } }

    # One address in a documentation range per host: 192.0.2.1-250, then 198.51.100.x, then 203.0.113.x.
    def ipv4
      range, octet = (index - 1).divmod(250)
      "#{%w[192.0.2 198.51.100 203.0.113].fetch(range)}.#{octet + 1}"
    end

    def ipv6 = "2001:db8::#{index.to_s(16)}"
  end
end
