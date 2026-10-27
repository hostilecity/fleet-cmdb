module AgentApi
  # Request validation against the JSON Schemas in docs/api/schemas, the single source of truth for the
  # agent API (FR-S.2, NFR-5, DEC-08).
  module Schema
    module_function

    def dir = AgentApi.config.schemas_dir

    def path(name, version) = dir.join("v#{version}", "#{name}.schema.json")

    def exists?(name, version) = version.is_a?(Integer) && version.positive? && path(name, version).file?

    def latest_version
      dir.children.filter_map { |child| child.basename.to_s[/\Av(\d+)\z/, 1]&.to_i }.max
    end

    def document(name, version)
      documents.compute_if_absent([ name, version ]) { JSON.parse(path(name, version).read) }
    end

    def schemer(name, version)
      schema = document(name, version) # loaded first: compute_if_absent blocks must not nest on one map
      schemers.compute_if_absent([ name, version ]) { JSONSchemer.schema(schema) }
    end

    # [{ "pointer" => "/field", "problem" => "..." }]; empty when valid. Problems never include values.
    def errors(name, version, data)
      schemer(name, version).validate(data).first(64).map do |error|
        { "pointer" => error.fetch("data_pointer").truncate(256), "problem" => error.fetch("error").truncate(256) }
      end
    end

    # JSON Pointers to keys the schema does not declare. These are ignored and logged (DEC-08).
    def undeclared_pointers(name, version, data)
      walk(document(name, version), data, "", [])
    end

    def walk(schema, value, pointer, out)
      return out unless schema.is_a?(Hash)

      case value
      when Hash
        properties = schema["properties"]
        return out unless properties

        value.each do |key, sub|
          child = "#{pointer}/#{key.to_s.gsub('~', '~0').gsub('/', '~1')}"
          properties.key?(key) ? walk(properties[key], sub, child, out) : out << child
        end
      when Array
        value.each_with_index { |sub, index| walk(schema["items"], sub, "#{pointer}/#{index}", out) } if schema["items"].is_a?(Hash)
      end
      out
    end

    def documents = (@documents ||= Concurrent::Map.new)

    def schemers = (@schemers ||= Concurrent::Map.new)
  end
end
