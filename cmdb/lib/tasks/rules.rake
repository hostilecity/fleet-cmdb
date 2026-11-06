# CIS-aligned rules (P2-S04, FR-2.2). Imports are audited with the system actor; the dashboard upload (P2-D06)
# uses the same import with the operator as actor.
namespace :rules do
  desc "Import CIS-aligned rules from a YAML or JSON file: FILE=rules.yml [DISABLE_MISSING=1]"
  task import: :environment do
    path = ENV.fetch("FILE") { abort "Usage: bin/rails rules:import FILE=rules.yml [DISABLE_MISSING=1]" }
    text = begin
      File.read(path, encoding: "UTF-8")
    rescue SystemCallError => e
      abort "Cannot read #{path}: #{e.message}"
    end
    result = CisRules::Import.call(text, actor: Audit::SYSTEM, disable_missing: ENV["DISABLE_MISSING"] == "1")
    abort "#{path} was not imported; nothing changed. #{result.errors.size} problem(s):\n  #{result.errors.join("\n  ")}" unless result.ok?

    %i[created versioned unchanged enabled disabled].each do |name|
      keys = result.public_send(name)
      puts "#{name.to_s.capitalize}: #{keys.size}#{": #{keys.join(', ')}" if keys.any? && name != :unchanged}"
    end
  end

  desc "List rules: key, current version, enabled, severity, and fact"
  task list: :environment do
    rules = CisRule.includes(:current_version).order(:key)
    puts "No rules. Import some with rules:import FILE=..." if rules.none?
    rules.each do |rule|
      version = rule.current_version
      puts [ rule.key, "v#{version.version}", rule.enabled ? "enabled" : "disabled", version.severity, version.fact ].join("  ")
    end
  end
end
