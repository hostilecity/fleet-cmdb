module CisRules
  # The rule evaluator (P2-S05, FR-2.2, DEC-12): a pure function of a rule, the host's facts, and its operating
  # system. It reads nothing else and writes nothing; P2-S06 stores what it returns.
  #
  #   CisRules::Evaluator.call(rule, facts, os) # => Outcome(result: "fail", observed: "yes", reason: nil)
  #
  # rule  anything with applies_to, fact, and condition (a CisRuleVersion or a CisRules::Definition)
  # facts { "<fact key>" => { "state" => "ok" | "unreadable" | "unsupported" | "missing", "value" => ..., "reason" => ... } },
  #       as a config snapshot stores them (P2-S02); a fact not in the hash is missing
  # os    { "id" => "debian", "version_id" => "13" } from the host's inventory, or nil when it has none
  #
  # Results, checked in this order:
  #   not_readable    the host's operating system is unknown; the fact is unreadable, unsupported, or missing (with
  #                   the agent's reason); its value does not fit the manifest; or matching ran out of time
  #   not_applicable  applies_to does not match the host
  #   pass, fail      the condition, with the observed value
  #
  # An absent value (null, which the manifest allows only for a file or unit that does not exist) passes only
  # absent, ne, and not_in: it equals nothing, is in nothing, matches nothing, and has no parts. An empty list
  # passes in, matches (every entry does), and not_in.
  #
  # Nothing in a rule is ever run as code: operators are dispatched
  # by name from a closed list (spec/lib/cis_rules/evaluator_spec.rb checks this file for eval, send, and shells).
  module Evaluator
    RESULTS = %w[pass fail not_applicable not_readable].freeze
    OBSERVED_MAX_BYTES = 1024
    REASON_MAX = 512
    TIME_BUDGET = 0.25 # seconds of matching per rule, however many list entries a value has

    Outcome = Data.define(:result, :observed, :reason)

    class OutOfTime < StandardError; end

    module_function

    def call(rule, facts, os, manifest: ConfigManifest.current)
      return not_readable("The host has not reported its operating system.") unless os.is_a?(Hash) && os["id"].is_a?(String)
      return Outcome.new(result: "not_applicable", observed: nil, reason: applicability(rule, os)) unless applies?(rule.applies_to, os)

      fact = manifest.fact(rule.fact)
      reported = facts[rule.fact]
      return not_readable("The host's report does not include this fact.") if reported.nil? || reported["state"] == "missing"
      return not_readable(reported["reason"].presence || "The agent reported this fact as #{reported['state']}.") unless reported["state"] == "ok"

      value = reported["value"]
      problems = fact.value_errors(value)
      return not_readable("The reported value does not fit the fact manifest: it #{problems.join(', ')}.") if problems.any?

      passed = holds?(rule.condition, fact.normalize(value), fact, deadline: Process.clock_gettime(Process::CLOCK_MONOTONIC) + TIME_BUDGET)
      Outcome.new(result: passed ? "pass" : "fail", observed: observed(value), reason: nil)
    rescue OutOfTime, Regexp::TimeoutError
      not_readable("Matching the value took longer than allowed, so it was not evaluated.")
    end

    def applies?(platforms, os)
      platforms.any? { |platform| platform["distribution"] == os["id"] && (platform["versions"].nil? || platform["versions"].include?(os["version_id"])) }
    end

    def applicability(rule, os)
      targets = rule.applies_to.map { |platform| [ platform["distribution"], *Array(platform["versions"]).join("/").presence ].join(" ") }
      "Applies to #{targets.join(', ')}; this host runs #{[ os['id'], os['version_id'] ].compact.join(' ')}.".truncate(REASON_MAX)
    end

    def holds?(node, value, fact, deadline:)
      if node.key?("all") then node["all"].all? { |child| holds?(child, value, fact, deadline:) }
      elsif node.key?("any") then node["any"].any? { |child| holds?(child, value, fact, deadline:) }
      elsif node.key?("not") then !holds?(node["not"], value, fact, deadline:)
      else
        name = Condition.operator(node)
        operate(name, node[name], select(value, node["field"]), fact, deadline:)
      end
    end

    # A file's or service's part; a missing file or unit has no parts.
    def select(value, field) = field && value ? value[field] : value

    def operate(name, operand, value, fact, deadline:)
      case name
      when "present" then !value.nil?
      when "absent" then value.nil?
      when "eq" then !value.nil? && value == comparable(operand, fact)
      when "ne" then value.nil? || value != comparable(operand, fact)
      when "in" then !value.nil? && entries(value).all? { |entry| operand.include?(entry) }
      when "not_in" then value.nil? || entries(value).none? { |entry| operand.include?(entry) }
      when "gte" then value.is_a?(Integer) && value >= operand
      when "lte" then value.is_a?(Integer) && value <= operand
      when "matches" then !value.nil? && matches?(operand, entries(value), deadline:)
      when "mode_at_most" then mode_at_most?(value.is_a?(Hash) ? value["mode"] : value, operand)
      else raise ArgumentError, "unknown operator #{name.inspect}" # the schema and Condition refuse it first
      end
    end

    # An operand list is compared as the fact compares lists: sorted unless the manifest says the order matters.
    def comparable(operand, fact) = operand.is_a?(Array) ? fact.normalize(operand) : operand

    def entries(value) = value.is_a?(Array) ? value : [ value ]

    def matches?(pattern, values, deadline:)
      regexp = Condition.regexp(pattern)
      values.all? do |entry|
        raise OutOfTime if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline

        entry.is_a?(String) && regexp.match?(entry)
      end
    end

    # No permission bit in the mode that the limit does not grant (special bits included).
    def mode_at_most?(mode, limit) = mode.is_a?(String) && (mode.to_i(8) & ~limit.to_i(8) & 0o7777).zero?

    # The value as reported, or, when its JSON is longer than OBSERVED_MAX_BYTES, that JSON cut short at a
    # character boundary and marked as truncated.
    def observed(value)
      json = value.to_json
      return value if json.bytesize <= OBSERVED_MAX_BYTES

      "#{json.byteslice(0, OBSERVED_MAX_BYTES - 64).scrub('')}… (truncated from #{json.bytesize} bytes)"
    end

    def not_readable(reason) = Outcome.new(result: "not_readable", observed: nil, reason: reason.to_s.truncate(REASON_MAX))

    private_class_method :applies?, :applicability, :holds?, :select, :operate, :comparable, :entries, :matches?, :mode_at_most?, :observed, :not_readable
  end
end
