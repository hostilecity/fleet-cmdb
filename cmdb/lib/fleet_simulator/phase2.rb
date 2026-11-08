require "tmpdir"

module FleetSimulator
  # Phase 2 data for the load check (P2-S12): configuration and package reports of a realistic size, and the
  # server-side data that makes the Phase 2 pages do real work: the starter CIS rules and advisories that affect the
  # simulated packages.
  #
  # Every simulated host runs the same PACKAGES packages, built from SOURCES source packages (a minimal Debian 13
  # server has about 400 to 900). The first VULNERABLE_SOURCES sources are affected by one simulated advisory each,
  # fixed in FIXED_VERSION. A host's package generation counts its upgrades: each one moves the next UPGRADE_STEP
  # vulnerable sources to the fixed version, so its findings resolve a few at a time as a real fleet's do.
  #
  # The advisories use ids in a range no real record uses (SIM-...), and their source packages (simsrc-...) exist
  # only on simulated hosts, so they can never match a real host.
  module Phase2
    PACKAGES = 800
    SOURCES = 300
    VULNERABLE_SOURCES = 150
    UPGRADE_STEP = 5
    VULNERABLE_VERSION = "1.4-1".freeze
    FIXED_VERSION = "2.0-1".freeze
    ADVISORY_SOURCE = "fleet-simulator".freeze
    RULES_FILE = Rails.root.join("config/rules/debian-13.yml")

    # The packages of a host at generation: [{ name, version, architecture, source }], as dpkg reports them.
    def self.packages(generation)
      upgraded = [ generation * UPGRADE_STEP, VULNERABLE_SOURCES ].min
      Array.new(PACKAGES) do |i|
        source = i % SOURCES
        version = source < VULNERABLE_SOURCES && source >= upgraded ? VULNERABLE_VERSION : FIXED_VERSION
        { "name" => format("simpkg-%04d", i), "version" => version, "architecture" => "amd64", "source" => source_name(source) }
      end
    end

    def self.source_name(index) = format("simsrc-%03d", index)

    # One OSV record per vulnerable source, in the shape osv.dev publishes for Debian.
    def self.advisory_records(modified: "2026-11-01T00:00:00Z")
      Array.new(VULNERABLE_SOURCES) do |i|
        { "id" => format("SIM-%04d", i + 1), "modified" => modified, "summary" => "Simulated advisory for #{source_name(i)}",
          "database_specific" => { "severity" => %w[low medium high critical][i % 4] },
          "affected" => [ { "package" => { "ecosystem" => "Debian:13", "name" => source_name(i) },
                            "ranges" => [ { "type" => "ECOSYSTEM", "events" => [ { "introduced" => "0" }, { "fixed" => FIXED_VERSION } ] } ] } ] }
      end
    end

    # Imports the starter CIS rules (when the server has no rules yet) and the simulated advisories, as an operator
    # would from the command line. Both are audited, as the system. Returns what it did, for the log.
    def self.prepare!
      rules = if CisRule.exists? then "kept the existing #{CisRule.count} CIS rules"
      else
        result = CisRules::Import.call(RULES_FILE.read, actor: Audit::SYSTEM, source: "rules_import") # as bin/rails rules:import
        "imported #{result.created.size} starter CIS rules"
      end
      Dir.mktmpdir("fleet-simulator-osv-") do |dir|
        advisory_records.each { |record| File.write(File.join(dir, "#{record['id']}.json"), JSON.generate(record)) }
        Advisories::Import.new(origin: "file", source: ADVISORY_SOURCE).call(Advisories::Reader.new(dir))
      end
      "#{rules}; imported #{VULNERABLE_SOURCES} simulated advisories"
    end

    # Evaluates CIS rules and matches advisories for the hosts now, so the pages have results however far the
    # server's own jobs have got. Both are idempotent, and the jobs the reports queued do the same work again.
    def self.evaluate!(host_ids)
      CisEvaluation.evaluate!(host_ids)
      VulnerabilityMatcher.match!(host_ids)
    end
  end
end
