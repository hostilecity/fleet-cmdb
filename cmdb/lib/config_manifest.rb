# The configuration fact manifest (FR-2.1, P2-S01): the versioned list of facts an agent may report, loaded from
# config/fact_manifest.yml, validated as a whole when it is loaded, and published at GET /api/v1/manifest/config.
# The same fact definitions validate the values in config reports (P2-S02) and are what rules inspect (P2-S05).
#
# Types (the contract for the report validator and the rule evaluator):
#   string           text, at most max_length characters
#   integer          a whole number from minimum to maximum
#   boolean          true or false
#   string_list      a list of at most max_items strings of at most item_max_length characters; `ordered` says
#                    whether the order carries meaning (ciphers do, running services do not). The server sorts
#                    a list that is not ordered, so a reordering is no change
#   file_attributes  {mode, owner, group} of a file, or null when the file does not exist
#   service_state    {active, enabled} of a systemd unit, or null when no such unit is installed
#
# The manifest names fact keys only, never commands: an agent decides how to read a fact it knows, and reports
# the rest as unsupported. A fact is never removed, renamed, or given another type (docs/operations/config-facts.md),
# so a report made against an older manifest version stays valid.
module ConfigManifest
  class Invalid < StandardError; end

  SCHEMA_VERSION = 1
  PATH = Rails.root.join("config/fact_manifest.yml")

  NAMED_KEY = /\A[a-z][a-z0-9_]*(\.[a-z0-9_]+)+\z/
  FILE_PATH = %r{\A/[A-Za-z0-9._/+-]{1,200}\z}
  UNIT_NAME = /\A[A-Za-z0-9._@+-]{1,100}\z/
  MODE = /\A[0-7]{3,4}\z/
  STATE_WORD = /\A[a-z][a-z-]{0,31}\z/
  SAFE_INTEGER = 2**53 - 1

  # Which constraints each type takes, with their defaults. Published as they are, so an agent bounds what it collects.
  CONSTRAINTS = {
    "string" => { "max_length" => 256 },
    "integer" => { "minimum" => -SAFE_INTEGER, "maximum" => SAFE_INTEGER },
    "boolean" => {},
    "string_list" => { "max_items" => 200, "item_max_length" => 256, "ordered" => false },
    "file_attributes" => {},
    "service_state" => {}
  }.freeze

  FILE_EXAMPLE = { "mode" => "0644", "owner" => "root", "group" => "root" }.freeze
  SERVICE_EXAMPLE = { "active" => "active", "enabled" => "enabled" }.freeze

  Fact = Data.define(:key, :type, :since, :description, :constraints, :example) do
    # Problems with a value for this fact, as sentences; empty when it is acceptable.
    def value_errors(value)
      case type
      when "string" then string_errors(value)
      when "integer" then integer_errors(value)
      when "boolean" then [ true, false ].include?(value) ? [] : [ "must be true or false" ]
      when "string_list" then list_errors(value)
      when "file_attributes" then file_errors(value)
      when "service_state" then service_errors(value)
      end
    end

    # What the manifest endpoint publishes for this fact.
    def as_json(*) = { "key" => key, "type" => type, "since" => since, "description" => description }.merge(constraints)

    # An unordered list in a canonical order; any other value as it is.
    def normalize(value) = type == "string_list" && !constraints["ordered"] && value.is_a?(Array) ? value.sort : value

    private

    def string_errors(value)
      return [ "must be a string" ] unless value.is_a?(String)

      value.length > constraints["max_length"] ? [ "is longer than #{constraints['max_length']} characters" ] : []
    end

    def integer_errors(value)
      return [ "must be an integer" ] unless value.is_a?(Integer)

      value.between?(constraints["minimum"], constraints["maximum"]) ? [] : [ "must be from #{constraints['minimum']} to #{constraints['maximum']}" ]
    end

    def list_errors(value)
      return [ "must be a list of strings" ] unless value.is_a?(Array) && value.all?(String)
      return [ "has more than #{constraints['max_items']} entries" ] if value.size > constraints["max_items"]

      value.any? { |item| item.length > constraints["item_max_length"] } ? [ "has an entry longer than #{constraints['item_max_length']} characters" ] : []
    end

    def file_errors(value)
      return [] if value.nil?
      return [ "must be null (no such file) or an object with mode, owner, and group" ] unless value.is_a?(Hash)

      errors = []
      errors << "mode must be an octal string such as \"0640\"" unless value["mode"].is_a?(String) && value["mode"].match?(MODE)
      %w[owner group].each { |name| errors << "#{name} must be a string of 1 to 64 characters" unless value[name].is_a?(String) && value[name].length.between?(1, 64) }
      errors
    end

    def service_errors(value)
      return [] if value.nil?
      return [ "must be null (no such unit) or an object with active and enabled" ] unless value.is_a?(Hash)

      %w[active enabled].filter_map { |name| "#{name} must be a lower-case word" unless value[name].is_a?(String) && value[name].match?(STATE_WORD) }
    end
  end

  # A loaded manifest: every fact (the listed ones, plus a file_attributes fact per file and a service_state fact
  # per service), keyed and sorted by key.
  class Manifest
    attr_reader :version, :facts

    def initialize(version:, facts:)
      @version = version
      @facts = facts.sort_by(&:key).freeze
      @by_key = @facts.index_by(&:key).freeze
    end

    def fact(key) = @by_key[key]
    def key?(key) = @by_key.key?(key)

    # The facts a report made against manifest version `version` is expected to contain.
    def facts_for(version) = facts.select { |fact| fact.since <= version }

    def as_json(*) = { "schema_version" => SCHEMA_VERSION, "manifest_version" => version, "facts" => facts.map(&:as_json) }

    def to_json(*) = @json ||= JSON.generate(as_json)

    # Changes whenever anything published changes.
    def etag = @etag ||= OpenSSL::Digest::SHA256.hexdigest(to_json)
  end

  module_function

  # The manifest the server publishes. Loaded once; a manifest that does not validate stops the first use with
  # every problem listed, and the spec suite loads it, so CI catches a bad edit.
  def current = @current ||= load(PATH)

  def reset! = @current = nil

  def load(path)
    data = YAML.safe_load_file(path, permitted_classes: [], aliases: false)
    errors = []
    facts = build(data, errors)
    raise Invalid, "#{path}: #{errors.join('; ')}" if errors.any?

    Manifest.new(version: data["manifest_version"], facts:)
  end

  def build(data, errors)
    unless data.is_a?(Hash)
      errors << "must be a mapping"
      return []
    end

    version = data["manifest_version"]
    errors << "manifest_version must be a positive integer" unless version.is_a?(Integer) && version.positive?
    facts = list(data, "facts", errors).filter_map { |entry| listed_fact(entry, errors) } +
            list(data, "files", errors).filter_map { |entry| path_fact(entry, errors) } +
            list(data, "services", errors).filter_map { |entry| unit_fact(entry, errors) }
    check_set(facts, version, errors)
    facts
  end

  def list(data, name, errors)
    entries = data[name]
    return entries if entries.is_a?(Array) && entries.all?(Hash)

    errors << "#{name} must be a list of mappings"
    []
  end

  def listed_fact(entry, errors)
    key = entry["key"].to_s
    type = entry["type"]
    errors << "#{key}: key must look like sshd.permitrootlogin" unless key.match?(NAMED_KEY)
    errors << "#{key}: ordered must be true or false" if entry.key?("ordered") && ![ true, false ].include?(entry["ordered"])
    unless CONSTRAINTS.key?(type)
      errors << "#{key}: unknown type #{type.inspect}"
      return nil
    end

    unknown = entry.keys - %w[key type since description example] - CONSTRAINTS.fetch(type).keys.map(&:to_s)
    errors << "#{key}: unknown or misplaced fields #{unknown.join(', ')}" if unknown.any?
    build_fact(key:, type:, entry:, constraints: CONSTRAINTS.fetch(type).to_h { |name, default| [ name, entry.fetch(name, default) ] }, example: entry["example"], errors:)
  end

  def path_fact(entry, errors)
    path = entry["path"].to_s
    errors << "#{path}: path must be absolute, with only letters, digits, and . _ / + -" unless path.match?(FILE_PATH)
    build_fact(key: "file:#{path}", type: "file_attributes", entry:, constraints: {}, example: FILE_EXAMPLE, errors:)
  end

  def unit_fact(entry, errors)
    unit = entry["unit"].to_s
    errors << "#{unit}: unit name is not valid" unless unit.match?(UNIT_NAME)
    entry = entry.merge("description" => "Whether the systemd unit #{unit} is active and whether it is enabled; null when it is not installed.")
    build_fact(key: "service:#{unit}", type: "service_state", entry:, constraints: {}, example: SERVICE_EXAMPLE, errors:)
  end

  def build_fact(key:, type:, entry:, constraints:, example:, errors:)
    since = entry["since"]
    description = entry["description"]
    errors << "#{key}: since must be a positive integer" unless since.is_a?(Integer) && since.positive?
    errors << "#{key}: description must be 1 to 512 characters" unless description.is_a?(String) && description.length.between?(1, 512)
    fact = Fact.new(key:, type:, since:, description:, constraints:, example:)
    problems = fact.value_errors(example)
    errors << "#{key}: its example #{problems.join(', ')}" if problems.any?
    fact
  end

  def check_set(facts, version, errors)
    facts.group_by(&:key).each { |key, same| errors << "#{key}: listed #{same.size} times" if same.size > 1 }
    return unless version.is_a?(Integer)

    errors << "manifest_version is #{version} but no fact has since #{version}, or one has a higher since" unless facts.map(&:since).max == version
  end

  private_class_method :build, :list, :listed_fact, :path_fact, :unit_fact, :build_fact, :check_set
end
