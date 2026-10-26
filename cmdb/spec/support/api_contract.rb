# Reads the agent API contract from docs/api (P0-CONTRACT, NFR-5). Schemas and examples live only
# there; server specs must load them through this module rather than keeping copies.
require "ipaddr"
require "json"
require "json_schemer"

module ApiContract
  ROOT = Rails.root.join("..", "docs", "api").expand_path

  # Values that are allowed to look like hostnames in examples (README: "Example data").
  FAKE_DOMAIN = /(\A|\.)(example\.(lan|com|net|org)|example|test|invalid)\z/
  DOC_RANGES = %w[192.0.2.0/24 198.51.100.0/24 203.0.113.0/24 2001:db8::/32].map { |r| IPAddr.new(r) }.freeze
  SECRET_KEYS = %w[token credential secret password].freeze

  Example = Struct.new(:path, :schema_name, :version, :kind, :name, keyword_init: true) do
    def data = JSON.parse(path.read)
    def to_s = path.relative_path_from(ROOT).to_s
  end

  module_function

  def versions
    ROOT.join("schemas").children.select(&:directory?).map { |d| d.basename.to_s }.sort
  end

  # Schema names for a version, e.g. "heartbeat.request".
  def schema_names(version)
    ROOT.join("schemas", version).glob("*.schema.json").map { |f| f.basename.to_s.delete_suffix(".schema.json") }.sort
  end

  def schema_path(name, version)
    ROOT.join("schemas", version, "#{name}.schema.json")
  end

  def schema(name, version)
    JSON.parse(schema_path(name, version).read)
  end

  def schemer(name, version)
    @schemers ||= {}
    @schemers[[ name, version ]] ||= JSONSchemer.schema(schema(name, version))
  end

  # Error messages from validating data against a schema; empty when valid.
  def errors(name, version, data)
    schemer(name, version).validate(data).map { |e| e.fetch("error") }
  end

  def examples
    ROOT.join("examples").glob("*/*/{valid,invalid}/*.json").sort.map do |path|
      kind_dir = path.dirname
      schema_dir = kind_dir.dirname
      Example.new(path: path, schema_name: schema_dir.basename.to_s, version: schema_dir.dirname.basename.to_s,
                  kind: kind_dir.basename.to_s, name: path.basename(".json").to_s)
    end
  end

  # Every property path a schema declares, e.g. "disks[].free_bytes". Follows local $refs, items,
  # and the *Of combinators.
  def declared_paths(node, root = node, prefix = nil, out = Set.new)
    return out unless node.is_a?(Hash)

    if (ref = node["$ref"])
      raise ArgumentError, "only local $refs are supported: #{ref}" unless ref.start_with?("#/")

      declared_paths(root.dig(*ref.delete_prefix("#/").split("/")), root, prefix, out)
    end
    node.fetch("properties", {}).each do |key, sub|
      path = [ prefix, key ].compact.join(".")
      out << path
      declared_paths(sub, root, path, out)
    end
    declared_paths(node["items"], root, "#{prefix}[]", out) if node["items"].is_a?(Hash)
    %w[allOf anyOf oneOf].each { |k| Array(node[k]).each { |sub| declared_paths(sub, root, prefix, out) } }
    out
  end

  # Every object key path present in a payload, in the same notation as declared_paths.
  def present_paths(value, prefix = nil, out = Set.new)
    case value
    when Hash
      value.each do |key, sub|
        path = [ prefix, key ].compact.join(".")
        out << path
        present_paths(sub, path, out)
      end
    when Array
      value.each { |sub| present_paths(sub, "#{prefix}[]", out) }
    end
    out
  end

  # Problems with example data that could be real: hostnames, addresses, secrets.
  def real_data_problems(value, key = nil, out = [])
    case value
    when Hash then value.each { |k, v| real_data_problems(v, k, out) }
    when Array then value.each { |v| real_data_problems(v, key, out) }
    when String then string_problems(value, key, out)
    end
    out
  end

  def string_problems(string, key, out)
    if SECRET_KEYS.include?(key) && !string.include?("EXAMPLE")
      out << "#{key} value #{string.inspect} does not contain EXAMPLE"
    end
    string.scan(%r{[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*|\d{1,3}(?:\.\d{1,3}){3}}).each do |candidate|
      address = parse_address(candidate) or next
      out << "address #{candidate} is outside the documentation ranges" unless DOC_RANGES.any? { |r| r.include?(address) }
    end
    string.scan(/[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/).each do |candidate|
      next unless candidate.split(".").last.match?(/\A[A-Za-z]{2,}\z/) # looks like a domain name

      out << "hostname #{candidate} is not under an example domain" unless candidate.downcase.match?(FAKE_DOMAIN)
    end
  end

  def parse_address(candidate)
    return nil unless candidate.count(":") >= 2 || candidate.count(".") == 3

    IPAddr.new(candidate)
  rescue IPAddr::Error
    nil
  end
end
