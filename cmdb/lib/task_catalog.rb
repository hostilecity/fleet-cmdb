# The task catalog (FR-3.1, P3-S01): the only task types the server may create, each with a closed parameter
# schema. Read from docs/api/tasks/task-catalog.json, the one file the agent also compiles in, so the two sides
# cannot drift; the server never builds a catalog entry from anything else, and never from request input.
#
#   TaskCatalog.current.entry("restart_service").parameter_errors({ "service" => "nginx.service" })  # => []
#
# The catalog lint (TaskCatalog.lint) runs whenever the file is loaded, so the server does not boot with a bad
# catalog (config/initializers/task_catalog.rb) and CI fails on a bad edit. It checks the file against
# task-catalog.schema.json, then what a schema cannot say:
# - every string parameter is bounded and has an enum or a strict pattern: anchored at both ends, built only from
#   letters, digits, and _ . @ + - (so never a space, a slash, or a shell character), with no `.` wildcard, no
#   negated class, and no escape but \. \- \+ \d;
# - no parameter name suggests a command, a program, its arguments or environment, or a path (repeated from the
#   schema, so loosening the schema alone does not loosen the lint);
# - parameter schemas are closed (additionalProperties false) and hold only strings, bounded integers, and booleans;
# - type ids are unique, versions line up, and only read_only types may run without a local opt-in (DEC-14).
# The file must be UTF-8 JSON without duplicate keys, because the agent and the server must read the same thing.
module TaskCatalog
  class Invalid < StandardError; end
  class UnknownType < StandardError; end

  FORMAT_VERSION = 1
  MAX_BYTES = 256.kilobytes
  MAX_PARAMETERS_BYTES = 4.kilobytes
  PRIVILEGES = %w[read_only service_manager package_manager].freeze

  # The image copies docs/api/tasks in from the "api" build context, as it does the agent API schemas.
  DIR = Pathname(ENV.fetch("FLEET_TASK_CATALOG_DIR") { Rails.root.join("../docs/api/tasks").to_s }).expand_path
  PATH = DIR.join("task-catalog.json")
  SCHEMA_PATH = DIR.join("task-catalog.schema.json")

  # The same two checks as the schema's parameter_name.
  COMMAND_LIKE_SUBSTRING = /command|cmd|shell|script|exec|eval|sudo|program|binary|executable/
  COMMAND_LIKE_WORD = /(\A|_)(args?|argv|argument|arguments|options?|flags?|env|environ|environment|paths?|file|files|filename|dir|directory|url|uri)(_|\z)/
  PATTERN_LITERAL = /[A-Za-z0-9_@+-]/
  PATTERN_SYNTAX = /[(){}|*+?,]/
  PATTERN_ESCAPES = %w[. - + d].freeze
  PATTERN_TIMEOUT = 0.1 # seconds; the patterns are short and simple, so this is never reached by a valid value

  # One problem: a JSON Pointer into the file ("" for the whole file) and what is wrong there.
  Problem = Data.define(:pointer, :message) do
    def to_s = "#{pointer.presence || '/'}: #{message}"
  end

  # One closed parameter, as the catalog declares it. pattern is the Ruby form of the catalog's pattern.
  Parameter = Data.define(:name, :type, :required, :min_length, :max_length, :enum, :pattern, :minimum, :maximum) do
    def errors(value)
      case type
      when "string" then string_errors(value)
      when "integer" then integer_errors(value)
      when "boolean" then [ true, false ].include?(value) ? [] : [ "must be true or false" ]
      end
    end

    private

    # Values are never echoed back: a message says what is wrong, not what was sent.
    def string_errors(value)
      return [ "must be a string" ] unless value.is_a?(String)
      return [ "must be at most #{max_length} characters" ] if value.length > max_length
      return [ "must be at least #{min_length} characters" ] if min_length && value.length < min_length
      return [ "must be one of #{enum.join(', ')}" ] if enum && !enum.include?(value)
      return [ "does not have the required form" ] if pattern && !pattern.match?(value)

      []
    end

    def integer_errors(value)
      return [ "must be a whole number" ] unless value.is_a?(Integer)

      value.between?(minimum, maximum) ? [] : [ "must be from #{minimum} to #{maximum}" ]
    end
  end

  # One task type. timeout and expiry are the catalog's defaults (ActiveSupport::Duration).
  Entry = Data.define(:type, :name, :description, :since, :privilege, :interruptible, :enabled_by_default,
                      :timeout, :expiry, :parameters) do
    # Problems with a task's parameters, each { "pointer" => "/service", "problem" => "..." }; empty when they are
    # acceptable. Extra fields, missing required ones, wrong types, oversize values, and values outside an enum or
    # pattern are all refused (P3-S01). Parameters are always an object, {} for a type that takes none.
    def parameter_errors(params)
      return [ problem("", "must be an object") ] unless params.is_a?(Hash) && params.keys.all?(String)
      return [ problem("", "must be at most #{MAX_PARAMETERS_BYTES} bytes as JSON") ] if JSON.generate(params).bytesize > MAX_PARAMETERS_BYTES

      by_name = parameters.index_by(&:name)
      errors = (params.keys - by_name.keys).sort.map { |key| problem("/#{escape(key)}", "is not a parameter of #{type}") }
      parameters.each do |parameter|
        if params.key?(parameter.name)
          errors.concat(parameter.errors(params[parameter.name]).map { |message| problem("/#{parameter.name}", message) })
        elsif parameter.required
          errors << problem("/#{parameter.name}", "is required")
        end
      end
      errors
    end

    def valid_parameters?(params) = parameter_errors(params).empty?

    def parameter_names = parameters.map(&:name)

    private

    def problem(pointer, message) = { "pointer" => pointer, "problem" => message }

    def escape(key) = key.to_s.truncate(64).gsub("~", "~0").gsub("/", "~1")
  end

  # A loaded catalog. digest is the SHA-256 of the file's bytes, the same bytes the agent compiles in.
  class Catalog
    attr_reader :version, :entries, :digest

    def initialize(version:, entries:, digest:)
      @version = version
      @entries = entries.freeze
      @by_type = entries.index_by(&:type).freeze
      @digest = digest
      freeze
    end

    def types = @by_type.keys

    def type?(type) = @by_type.key?(type)

    # Raises UnknownType for a type the catalog does not have.
    def entry(type) = @by_type.fetch(type) { raise UnknownType, "#{type.to_s.truncate(64).inspect} is not in the task catalog" }
  end

  module_function

  # The catalog the server uses. Loaded at boot (config/initializers/task_catalog.rb); a catalog that fails the
  # lint stops the server with every problem listed.
  def current = @current ||= load(PATH)

  def reset! = @current = nil

  def load(path)
    text = File.binread(path)
    problems = lint(text)
    raise Invalid, "#{path}: #{problems.join('; ')}" if problems.any?

    build(parse_json(text), Digest::SHA256.hexdigest(text))
  end

  # The catalog lint: every problem with a catalog file's text, as Problems; empty when the file is acceptable.
  def lint(text)
    return [ Problem.new("", "is larger than #{MAX_BYTES} bytes") ] if text.bytesize > MAX_BYTES
    return [ Problem.new("", "is not UTF-8") ] unless text.dup.force_encoding(Encoding::UTF_8).valid_encoding?

    data = begin
      parse_json(text)
    rescue JSON::ParserError => e
      return [ Problem.new("", "is not valid JSON (#{e.message.truncate(200)})") ]
    end
    schema_problems = schemer.validate(data).first(100).map { |error| Problem.new(error.fetch("data_pointer"), error.fetch("error").truncate(300)) }
    (semantic_problems(data) + schema_problems).uniq
  end

  def schemer = @schemer ||= JSONSchemer.schema(JSON.parse(SCHEMA_PATH.read), regexp_resolver: "ecma")

  def parse_json(text) = JSON.parse(text.dup.force_encoding(Encoding::UTF_8), allow_duplicate_key: false, max_nesting: 16)

  # The checks a schema cannot express. They read only the parts of the file that have the right shape, so they run
  # beside the schema's problems and name the rule that was broken, not only where the schema stopped matching.
  def semantic_problems(data)
    return [] unless data.is_a?(Hash) && data["tasks"].is_a?(Array)

    problems = []
    tasks = data["tasks"].select { |task| task.is_a?(Hash) }
    tasks.group_by { |task| task["type"] }.each { |type, same| problems << Problem.new("/tasks", "#{type} is listed #{same.size} times") if same.size > 1 }
    sinces = tasks.map { |task| task["since"] }.grep(Integer)
    version = data["catalog_version"]
    if version.is_a?(Integer) && sinces.any? && sinces.max != version
      problems << Problem.new("/catalog_version", "is #{version} but the highest since is #{sinces.max}; they must be equal")
    end
    data["tasks"].each_with_index { |task, index| problems.concat(task_problems(task, "/tasks/#{index}")) if task.is_a?(Hash) }
    problems
  end

  def task_problems(task, pointer)
    problems = []
    if task["enabled_by_default"] == true && task["privilege"] != "read_only"
      problems << Problem.new("#{pointer}/enabled_by_default", "only read_only task types may be enabled by default (DEC-14)")
    end
    schema = task["parameters"]
    return problems unless schema.is_a?(Hash)

    problems << Problem.new("#{pointer}/parameters/additionalProperties", "must be false") unless schema["additionalProperties"] == false
    properties = schema["properties"].is_a?(Hash) ? schema["properties"] : {}
    (Array(schema["required"]) - properties.keys).each { |name| problems << Problem.new("#{pointer}/parameters/required", "names #{name}, which is not a parameter") }
    properties.each { |name, spec| problems.concat(parameter_problems(name.to_s, spec, "#{pointer}/parameters/properties/#{name}")) }
    problems
  end

  def parameter_problems(name, spec, pointer)
    problems = []
    problems << Problem.new(pointer, "the name #{name} suggests a command, its arguments or environment, or a path") if command_like?(name)
    return problems unless spec.is_a?(Hash)

    case spec["type"]
    when "string" then problems.concat(string_problems(spec, pointer))
    when "integer"
      minimum, maximum = spec.values_at("minimum", "maximum")
      problems << Problem.new(pointer, "minimum is above maximum") if minimum.is_a?(Integer) && maximum.is_a?(Integer) && minimum > maximum
    when "boolean" then nil
    else problems << Problem.new("#{pointer}/type", "must be string, integer, or boolean")
    end
    problems
  end

  def command_like?(name) = name.match?(COMMAND_LIKE_SUBSTRING) || name.match?(COMMAND_LIKE_WORD)

  def string_problems(spec, pointer)
    problems = []
    if spec["enum"].nil? && spec["pattern"].nil?
      problems << Problem.new(pointer, "a string parameter needs an enum or a pattern; free-form strings are not allowed")
    end
    min_length = spec["minLength"].is_a?(Integer) ? spec["minLength"] : 0
    max_length = spec["maxLength"]
    return problems << Problem.new(pointer, "a string parameter needs a maxLength") unless max_length.is_a?(Integer)

    problems << Problem.new(pointer, "minLength is above maxLength") if min_length > max_length
    pattern = nil
    if spec["pattern"].is_a?(String)
      pattern_problems = strict_pattern_problems(spec["pattern"])
      problems.concat(pattern_problems.map { |message| Problem.new("#{pointer}/pattern", message) })
      pattern = ruby_pattern(spec["pattern"]) if pattern_problems.empty?
    end
    Array(spec["enum"]).each_with_index do |value, index|
      fits = value.is_a?(String) && value.length.between?(min_length, max_length) && (pattern.nil? || pattern.match?(value))
      problems << Problem.new("#{pointer}/enum/#{index}", "does not fit the parameter's own length or pattern") unless fits
    end
    problems
  end

  # Why a pattern is not strict enough; empty when it is. See the module comment for the rules.
  def strict_pattern_problems(source)
    body = source.delete_prefix("^").delete_suffix("$")
    return [ "must start with ^ and end with $" ] unless source.start_with?("^") && source.end_with?("$") && !source.end_with?("\\$")

    problems = []
    in_class = false
    chars = body.chars
    index = 0
    while index < chars.size
      char = chars[index]
      if char == "\\"
        escaped = chars[index + 1]
        problems << "uses the escape \\#{escaped}; only \\. \\- \\+ and \\d are allowed" unless PATTERN_ESCAPES.include?(escaped)
        index += 2
        next
      end
      if in_class
        if char == "]" then in_class = false
        elsif !(char.match?(PATTERN_LITERAL) || char == ".")
          problems << "a character class may hold only letters, digits, and _ . @ + -, not #{char.inspect}"
        end
      elsif char == "["
        problems << "uses a negated character class" if chars[index + 1] == "^"
        in_class = true
      elsif char == "."
        problems << "uses . outside a character class, which matches any character"
      elsif char == "(" && chars[index + 1] == "?"
        problems << "uses a special group"
      elsif !(char.match?(PATTERN_LITERAL) || char.match?(PATTERN_SYNTAX))
        problems << "may only match letters, digits, and _ . @ + -, not #{char.inspect}"
      end
      index += 1
    end
    problems << "has a character class that is not closed" if in_class
    problems.concat(compile_problems(source)) if problems.empty?
    problems.uniq
  end

  def compile_problems(source)
    ruby_pattern(source)
    []
  rescue RegexpError => e
    [ "does not compile (#{e.message.truncate(100)})" ]
  end

  # The catalog's ECMA-262 pattern in Ruby: ^ and $ become \A and \z, so a value cannot end in a newline. The lint
  # allows ^ and $ only at the two ends, so this is the whole difference for the patterns it accepts.
  def ruby_pattern(source) = Regexp.new("\\A#{source.delete_prefix('^').delete_suffix('$')}\\z", timeout: PATTERN_TIMEOUT)

  def build(data, digest)
    entries = data["tasks"].map do |task|
      schema = task["parameters"]
      parameters = schema["properties"].map do |name, spec|
        Parameter.new(name:, type: spec["type"], required: schema["required"].include?(name), min_length: spec["minLength"],
                      max_length: spec["maxLength"], enum: spec["enum"]&.freeze, pattern: spec["pattern"] && ruby_pattern(spec["pattern"]),
                      minimum: spec["minimum"], maximum: spec["maximum"])
      end
      Entry.new(type: task["type"], name: task["name"], description: task["description"], since: task["since"],
                privilege: task["privilege"], interruptible: task["interruptible"], enabled_by_default: task["enabled_by_default"],
                timeout: task["timeout_seconds"].seconds, expiry: task["expiry_seconds"].seconds, parameters: parameters.freeze)
    end
    Catalog.new(version: data["catalog_version"], entries:, digest:)
  end

  private_class_method :parse_json, :semantic_problems, :task_problems, :parameter_problems, :command_like?, :string_problems,
                       :compile_problems, :build
end
