# CIS-aligned rules (FR-2.2, DEC-10, DEC-12): data, never code. A rule names one fact from the config fact
# manifest (ConfigManifest) and a condition built from a closed set of operators. Rule files are YAML (or
# JSON) validated against docs/api/rules/v1/cis-rules.schema.json and then against the manifest, as a whole,
# before anything is stored (CisRules::RuleFile, P2-S04).
#
#   CisRules::Import.call(File.read("rules.yml"), actor: Audit::SYSTEM)
#
# Storage is CisRule (the stable key and enabled flag) and CisRuleVersion (one immutable row per definition).
module CisRules
  FORMAT_VERSION = 1
  # The image copies docs/api/rules in from the "api" build context, as it does the agent API schemas.
  SCHEMA_PATH = Pathname(ENV.fetch("FLEET_RULES_SCHEMA_DIR") { Rails.root.join("../docs/api/rules").to_s }).expand_path.join("v1/cis-rules.schema.json")
  SEVERITIES = %w[low medium high critical].freeze
  DEFINITION_FIELDS = %w[reference title severity applies_to fact condition remediation].freeze

  # Everything a version of a rule says. Its content hash decides whether an import creates a new version.
  Definition = Data.define(:key, :reference, :title, :severity, :applies_to, :fact, :condition, :remediation) do
    def self.from_h(rule) = new(key: rule.fetch("key"), **DEFINITION_FIELDS.to_h { |name| [ name.to_sym, rule.fetch(name) ] })

    # The definition's fields except the key, as stored and audited.
    def fields = DEFINITION_FIELDS.to_h { |name| [ name, public_send(name) ] }

    def content_hash = Digest::SHA256.hexdigest(CisRules.canonical_json(fields))
  end

  module_function

  # JSON with object keys sorted at every level, so equal definitions hash equally whatever the file's order.
  def canonical_json(value) = JSON.generate(canonical(value))

  def canonical(value)
    case value
    when Hash then value.map { |key, sub| [ key.to_s, canonical(sub) ] }.sort_by(&:first).to_h
    when Array then value.map { |item| canonical(item) }
    else value
    end
  end

  # Patterns follow ECMA-262, as JSON Schema says: `$` is the end of the string, so "key\n" does not pass.
  def schemer = @schemer ||= JSONSchemer.schema(JSON.parse(SCHEMA_PATH.read), regexp_resolver: "ecma")

  # One rule on its own, so the file's other checks run only on rules whose shape is right.
  def rule_schemer = @rule_schemer ||= schemer.ref("#/$defs/rule")

  private_class_method :canonical
end
