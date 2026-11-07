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

    # One problem: a JSON Pointer ("/" for the whole document) and what is wrong there.
    Problem = Data.define(:pointer, :message) do
      def to_s = "#{pointer}: #{message}"
    end

    RULE_POINTER = "/rules/0" # where parse_rule puts the rule it is given

    attr_reader :rules, :problems

    def self.parse(text, manifest: ConfigManifest.current) = new(manifest, text:).freeze

    # One rule on its own (a Hash, as a file holds it), as the dashboard edits it (P2-S14): the same checks as a
    # file, with each pointer into the rule rather than the file ("/condition/eq", not "/rules/0/condition/eq").
    def self.parse_rule(rule, manifest: ConfigManifest.current) = new(manifest, rule:).freeze

    # ["<pointer>: <message>"]
    def errors = problems.map(&:to_s)

    def valid? = problems.empty?

    private

    def initialize(manifest, text: nil, rule: nil)
      @manifest = manifest
      @rules = []
      @problems = []
      data = text ? read(text) : wrap(rule)
      nul_problems(data) if @problems.empty?
      validate(data) if @problems.empty? # a file that could not be read, or holds a NUL, has nothing more to check
      @rules = [] if @problems.any?
      @problems = @problems.first(MAX_ERRORS)
      @problems = @problems.map { |problem| problem.with(pointer: within_rule(problem.pointer)) } unless text
    end

    def read(text)
      return problem("/", "is larger than #{MAX_BYTES / 1.megabyte} MiB") if text.bytesize > MAX_BYTES
      return problem("/", "is not UTF-8 text") unless text.dup.force_encoding(Encoding::UTF_8).valid_encoding?

      plain(YAML.safe_load(text, permitted_classes: [], aliases: false))
    rescue Psych::Exception => e
      problem("/", "is not a plain YAML or JSON document (#{e.message.truncate(200)})")
    end

    def wrap(rule)
      rule = plain(rule)
      { "format_version" => FORMAT_VERSION, "rules" => [ rule ] } if @problems.empty?
    end

    # Through JSON, so keys are strings and anything JSON cannot hold (such as .nan) is refused here.
    def plain(data)
      json = JSON.generate(data, max_nesting: JSON_NESTING)
      return problem("/", "is larger than #{MAX_BYTES / 1.megabyte} MiB") if json.bytesize > MAX_BYTES

      JSON.parse(json, max_nesting: JSON_NESTING)
    rescue JSON::NestingError
      problem("/", "is nested more than #{JSON_NESTING} levels deep")
    rescue JSON::GeneratorError
      problem("/", "holds a value JSON cannot represent, such as NaN or infinity")
    end

    def within_rule(pointer)
      return pointer unless pointer == RULE_POINTER || pointer.start_with?("#{RULE_POINTER}/")

      pointer.delete_prefix(RULE_POINTER).presence || "/"
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

        Condition.problems(rule["condition"], fact, "#{pointer}/condition").each { |at, message| problem(at, message) }
        @rules << Rule.new(definition: Definition.from_h(rule), enabled: rule["enabled"])
      end
    end

    def problem(pointer, message)
      @problems << Problem.new(pointer: pointer.presence || "/", message:)
      nil
    end
  end
end
