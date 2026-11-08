require "json"

module FleetSimulator
  # Request bodies for simulated hosts, built from the shared examples in docs/api/examples (P0-CONTRACT), so the
  # simulator sends what the contract documents rather than its own idea of it.
  class Payloads
    EXAMPLES = Rails.root.join("../docs/api/examples/v1").expand_path

    # Markup that must be rendered escaped, a right-to-left override, and a zero-width space. Within the schema's
    # limits, so the server stores it and the dashboard has to cope with it.
    HOSTILE = %(<script>alert("sim")</script><img src=x onerror=alert(1)> ‮gnp.exe​).freeze

    def self.example(name, file) = JSON.parse(EXAMPLES.join(name, "valid", "#{file}.json").read)

    def initialize(agent_version:)
      @agent_version = agent_version
      @heartbeat = self.class.example("heartbeat.request", "typical")
      @inventory = self.class.example("inventory.request", "full")
      @onboarding = self.class.example("onboarding.request", "full")
      @enroll = self.class.example("enroll.request", "full")
      @config = self.class.example("config.request", "typical")
      @packages = self.class.example("packages.request", "dpkg")
    end

    def heartbeat(host, now:)
      @heartbeat.merge("agent_version" => @agent_version, "hostname" => host.hostname,
                       "uptime_seconds" => uptime(host, now), "agent_time" => now.utc.iso8601(3))
    end

    # A full report with a fresh report id. A churning host moves to a new kernel version every time.
    def inventory(host, now:, change_stable: host.churn?)
      host.generation += 1 if change_stable
      report = deep_copy(@inventory).merge(
        "agent_version" => @agent_version, "report_id" => SecureRandom.uuid, "collected_at" => now.utc.iso8601,
        "hostname" => host.hostname, "machine_id" => host.machine_id, "boot_id" => host.boot_id,
        "uptime_seconds" => uptime(host, now), "kernel_version" => "6.12.0-sim.#{host.generation}-amd64",
        "network_interfaces" => [ { "name" => "ens18", "primary" => true, "addresses" => [ "#{host.ipv4}/24", "#{host.ipv6}/64" ] } ]
      )
      # Volatile figures move a little on every report, as they do on a real machine.
      report["memory_available_bytes"] = report["memory_total_bytes"] / 2 + rand(1 << 26)
      report["disks"].each { |disk| disk["free_bytes"] = disk["size_bytes"] / 2 + rand(1 << 26) }
      hostile!(report) if host.hostile?
      report
    end

    # A configuration report (P2-S12): the documented typical facts. Each config generation flips the SSH root login
    # setting, so a host that changes writes a new snapshot and moves a CIS result (AC-2.1's shape).
    def config(host, now:)
      report = deep_copy(@config).merge("agent_version" => @agent_version, "report_id" => SecureRandom.uuid, "collected_at" => now.utc.iso8601)
      report["facts"]["sshd.permitrootlogin"] = { "state" => "ok", "value" => host.config_generation.odd? ? "yes" : "no", "reason" => nil }
      report
    end

    # A package report (P2-S12) of Phase2::PACKAGES packages at the host's package generation.
    def packages(host, now:)
      @packages.merge("agent_version" => @agent_version, "report_id" => SecureRandom.uuid, "collected_at" => now.utc.iso8601,
                      "packages" => Phase2.packages(host.package_generation))
    end

    # Facts for POST /api/v1/onboarding.
    def onboarding(host)
      @onboarding.merge("agent_version" => @agent_version, "hostname" => host.hostname, "machine_id" => host.machine_id)
    end

    def enroll(host, token)
      @enroll.merge("token" => token, "agent_version" => @agent_version, "hostname" => host.hostname, "machine_id" => host.machine_id)
    end

    private

    def uptime(host, now) = (now - host.started_at).to_i

    def hostile!(report)
      report["os"]["pretty_name"] = HOSTILE
      report["cpu_model"] = HOSTILE
      report["disks"].first["filesystem"] = "ext4 #{HOSTILE}".first(64)
      report["network_interfaces"].first["name"] = "ens18​"
    end

    def deep_copy(value) = JSON.parse(JSON.generate(value))
  end
end
