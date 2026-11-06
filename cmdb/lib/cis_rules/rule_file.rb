module CisRules
  # A rule file, parsed and validated as a whole (P2-S04): YAML read safely (no objects, no aliases), then the
  # JSON Schema in docs/api/rules, then each rule against the fact manifest (CisRules::Condition). Every problem
  # is listed with a JSON Pointer into the file; a file with any problem is never imported.
  class RuleFile
    MAX_BYTES = 1.megabyte
    MAX_ERRORS = 200
    JSON_NESTING = 64 # far more than a valid file needs (a condition nests at most 8 deep), and far less than would strain the parsers

    # enabled is nil when the file does not say, so an import leaves an existing rule's flag as it is.
    Rule = Data.define(:definition, :enabled)

    attr_reader :rules, :errors

    def self.parse(text, manifest: ConfigManifest.current) = new(text, manifest).freeze

    def valid? = errors.empty?

    private

    def initialize(text, manifest)
      @manifest = manifest
      @rules = []
      @errors = []
      data = read(text)
      nul_problems(data) if @errors.empty?
      validate(data) if @errors.empty? # a file that could not be read, or holds a NUL, has nothing more to check
      @rules = [] if @errors.any?
      @errors = @errors.first(MAX_ERRORS)
    end

    def read(text)
      return problem("/", "is larger than #{MAX_BYTES / 1.megabyte} MiB") if text.bytesize > MAX_BYTES
      return problem("/", "is not UTF-8 text") unless text.dup.force_encoding(Encoding::UTF_8).valid_encoding?

      # Through JSON, so keys are strings and anything JSON cannot hold (such as .nan) is refused here.
      JSON.parse(JSON.generate(YAML.safe_load(text, permitted_classes: [], aliases: false), max_nesting: JSON_NESTING), max_nesting: JSON_NESTING)
    rescue Psych::Exception => e
      problem("/", "is not a plain YAML or JSON document (#{e.message.truncate(200)})")
    rescue JSON::NestingError
      problem("/", "is nested more than #{JSON_NESTING} levels deep")
    rescue JSON::GeneratorError
      problem("/", "holds a value JSON cannot represent, such as NaN or infinity")
    end

    # PostgreSQL cannot store U+0000 in text or jsonb, so a NUL anywhere is a problem in the file, not a
    # failed write (review of #101).
    def nul_problems(value, pointer = "")
      case value
      when Hash
        value.each do |key, sub|
          problem(pointer, "has a key containing a NUL character") if key.include?("\0")
          nul_problems(sub, "#{pointer}/#{escape(key)}")
        end
      when Array then value.each_with_index { |sub, index| nul_problems(sub, "#{pointer}/#{index}") }
      when String then problem(pointer, "contains a NUL character") if value.include?("\0")
      end
    end

    def escape(key) = key.gsub("~", "~0").gsub("/", "~1")

    def validate(data)
      CisRules.schemer.validate(data).each { |error| problem(error.fetch("data_pointer"), error.fetch("error").sub(/\A\w+ at (`[^`]*`|root) /, "")) }
      return unless data.is_a?(Hash) && data["rules"].is_a?(Array)

      seen = {}
      data["rules"].each_with_index do |rule, index|
        next unless CisRules.rule_schemer.valid?(rule) # its problems are listed above; checking the rest would only add noise

        pointer = "/rules/#{index}"
        if (first = seen[rule["key"]])
          problem("#{pointer}/key", "#{rule['key']} is already used by /rules/#{first}")
        else
          seen[rule["key"]] = index
        end
        fact = @manifest.fact(rule["fact"])
        next problem("#{pointer}/fact", "#{rule['fact']} is not in the fact manifest") unless fact

        @errors.concat(Condition.errors(rule["condition"], fact, "#{pointer}/condition"))
        @rules << Rule.new(definition: Definition.from_h(rule), enabled: rule["enabled"])
      end
    end

    def problem(pointer, message)
      @errors << "#{pointer.presence || '/'}: #{message}"
      nil
    end
  end
end
