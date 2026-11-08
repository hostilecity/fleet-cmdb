module CisRules
  # What a rule condition may say about the fact it inspects (DEC-12, P2-S04). The JSON Schema checks the shape
  # (one operator or combinator per node, operand shapes); this checks the condition against the fact's type in
  # the manifest, so a rule that could never be evaluated is refused when it is imported rather than failing
  # on every host later.
  #
  # Operators, and the value types they take (a `field` makes the value a file's mode, owner, or group, or a
  # service's active or enabled state, which are strings):
  #   eq, ne            string, integer, boolean, or string_list (a list operand, compared as the fact compares)
  #   in, not_in        string, integer, boolean (one of / none of), or string_list (every entry / no entry)
  #   gte, lte          integer
  #   matches           string, or string_list (every entry); anchored at both ends and time-limited
  #   mode_at_most      file_attributes (its mode)
  #   present, absent   file_attributes, service_state: whether the value is null (no such file or unit; other
  #                     facts always have a value when they are readable)
  # Combinators all, any, and not combine conditions on the same fact.
  module Condition
    OPERATORS = %w[eq ne in not_in present absent gte lte matches mode_at_most].freeze
    COMBINATORS = %w[all any not].freeze
    FIELDS = { "file_attributes" => %w[mode owner group], "service_state" => %w[active enabled] }.freeze
    WHOLE_VALUE_OPERATORS = %w[present absent mode_at_most].freeze # the only ones that take a file or service without a field
    NOUNS = { "string" => "a string", "integer" => "an integer", "boolean" => "a boolean", "string_list" => "a list of strings" }.freeze
    MAX_DEPTH = 8
    MAX_NODES = 64
    REGEXP_TIMEOUT = 0.05 # seconds per match; a hostile fact value cannot hold the evaluator longer

    module_function

    def operator(node) = OPERATORS.find { |name| node.key?(name) }

    def combinator(node) = COMBINATORS.find { |name| node.key?(name) }

    # The type of value an operator in this node sees.
    def value_type(fact_type, field) = field ? "string" : fact_type

    # The pattern anchored at both ends and limited in time. Raises RegexpError for a pattern that does not
    # compile on its own, so an unbalanced group cannot escape the anchors.
    def regexp(pattern)
      Regexp.new(pattern)
      Regexp.new("\\A(?:#{pattern})\\z", timeout: REGEXP_TIMEOUT)
    end

    # ["<pointer>: <problem>"] for a condition the JSON Schema accepted; empty when it fits the fact.
    def errors(condition, fact, pointer) = problems(condition, fact, pointer).map { |at, problem| "#{at}: #{problem}" }

    # [[pointer, problem]], as errors, with the pointer kept apart (P2-S14 shows each problem beside its field).
    def problems(condition, fact, pointer)
      state = { nodes: 0, out: [] }
      check(condition, fact, pointer, 1, state)
      state[:out] << [ pointer, "has more than #{MAX_NODES} conditions" ] if state[:nodes] > MAX_NODES
      state[:out]
    end

    def check(node, fact, pointer, depth, state)
      state[:nodes] += 1
      return state[:out] << [ pointer, "is nested more than #{MAX_DEPTH} deep" ] if depth > MAX_DEPTH

      if (name = combinator(node))
        children = name == "not" ? [ [ node["not"], "#{pointer}/not" ] ] : node[name].each_with_index.map { |child, i| [ child, "#{pointer}/#{name}/#{i}" ] }
        children.each { |child, child_pointer| check(child, fact, child_pointer, depth + 1, state) }
      else
        problem = operator_problem(operator(node), node, fact)
        state[:out] << [ pointer, problem ] if problem
      end
    end

    def operator_problem(name, node, fact)
      field = node["field"]
      fields = FIELDS[fact.type]
      return "field #{field} is not part of a #{fact.type} value" if field && !fields&.include?(field)
      return "#{name} needs a field for a #{fact.type} fact (#{fields.join(', ')})" if fields && !field && !WHOLE_VALUE_OPERATORS.include?(name)

      operand_problem(name, node, value_type(fact.type, field), fact)
    end

    def operand_problem(name, node, type, fact)
      operand = node[name]
      case name
      when "eq", "ne" then "#{name} #{fits(type, operand)}" unless fits?(type, operand)
      when "in", "not_in"
        item_type = type == "string_list" ? "string" : type
        "#{name} needs a list of #{item_type}s#{yaml_hint(item_type, operand)}" unless operand.all? { |item| fits?(item_type, item) }
      when "present", "absent" then "#{name} works only on a file or service fact; #{fact.key} always has a value when it is readable" unless FIELDS.key?(fact.type) && node["field"].nil?
      when "gte", "lte" then "#{name} works only on an integer fact, and #{fact.key} is #{type}" unless type == "integer"
      when "matches" then matches_problem(operand, type, fact)
      when "mode_at_most" then "mode_at_most works only on a file fact, or its mode field" unless fact.type == "file_attributes" && [ nil, "mode" ].include?(node["field"])
      end
    end

    def matches_problem(pattern, type, fact)
      return "matches works only on a string or list fact, and #{fact.key} is #{type}" unless %w[string string_list].include?(type)

      regexp(pattern)
      nil
    rescue RegexpError => e
      "matches is not a valid regular expression (#{e.message.truncate(120)})"
    end

    def fits?(type, operand)
      case type
      when "string" then operand.is_a?(String)
      when "integer" then operand.is_a?(Integer)
      when "boolean" then operand == true || operand == false
      when "string_list" then operand.is_a?(Array) && operand.all?(String)
      end
    end

    def fits(type, operand) = "needs #{NOUNS.fetch(type)}#{yaml_hint(type, operand)}"

    # YAML 1.1 reads an unquoted yes, no, on, or off as a boolean, the usual reason a string comparison fails.
    def yaml_hint(type, operand)
      booleans = Array(operand).any? { |item| item == true || item == false }
      type == "string" && booleans ? " (quote yes, no, on, and off in YAML, or they are read as true and false)" : ""
    end

    private_class_method :check, :operator_problem, :operand_problem, :matches_problem, :fits?, :fits, :yaml_hint
  end
end
