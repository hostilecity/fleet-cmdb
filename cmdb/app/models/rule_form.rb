# The add-rule and edit-rule form (P2-D06, approved mockups rule-create.html, rule-edit.html, rule-edit-errors.html):
# what the operator typed, turned into a rule as a rule file holds one, and the problems the import's checks
# (CisRules::RuleFile.parse_rule) found in it, each placed beside the field it is about with its JSON Pointer.
#
# - A single comparison (one of OPERATORS on the fact itself) is an operator and an expected value, read as the
#   fact's type says: an integer fact takes an integer, a boolean fact true or false (yes and no too, since the
#   form knows the type), a list takes comma-separated entries. Anything else (all, any, not, a field of a file
#   or service, matches, mode_at_most, present, absent) is edited as YAML or JSON text. A new rule is always a
#   single comparison; a rule with several conditions comes in by importing a file (owner decision Q11).
# - The form is never trusted to be valid: every rule it builds goes through the import's checks before a preview
#   or a save, so the form cannot store anything an import would refuse.
class RuleForm
  OPERATORS = { "eq" => "equal to", "ne" => "not equal to", "in" => "one of", "not_in" => "not one of", "gte" => "at least", "lte" => "at most" }.freeze
  LIST_OPERATORS = %w[in not_in].freeze
  INTEGER_OPERATORS = %w[gte lte].freeze
  # The facts a single comparison can test: a file or service fact needs a field, so its rules are edited as text.
  SINGLE_TYPES = %w[string integer boolean string_list].freeze
  TEXT_FIELDS = %w[key title reference severity fact remediation].freeze
  CONDITION_TEXT_MAX = 64.kilobytes
  MAX_PLATFORMS = 16 # as the schema's applies_to; the form shows the rows given plus one empty row for another
  TRUE_WORDS = %w[true yes].freeze
  FALSE_WORDS = %w[false no].freeze

  # Where a problem is shown: the field its pointer starts in (applies_to for anything under /applies_to), or :base.
  FIELD_LABELS = { "key" => "Key", "title" => "Title", "reference" => "Reference", "severity" => "Severity", "applies_to" => "Applies to",
                   "fact" => "Fact", "condition" => "Condition", "remediation" => "Remediation", "enabled" => "Enabled" }.freeze

  Platform = Data.define(:distribution, :versions)
  # One problem: the field it belongs to, the JSON Pointer into the rule, and the message.
  Problem = Data.define(:field, :pointer, :message) do
    # Whether the pointer says more than the field it is shown beside (/condition/all/0, not just /reference).
    def deep? = pointer != "/#{field}"
  end

  # rule_hash: the rule valid? checked, as a rule file holds it (the dry run and saving take this).
  attr_reader :rule_hash, :key, :title, :reference, :severity, :fact, :operator, :expected, :condition_text, :remediation, :platforms, :problems

  # The form for a stored rule, filled from its current version.
  def self.for_rule(rule)
    version = rule.current_version
    form = new(rule:)
    form.send(:load_version, version)
    form
  end

  # A condition as a rule file writes it in YAML, with each node's field before its operator (the database keeps
  # jsonb keys in its own order).
  def self.condition_yaml(condition) = YAML.dump(field_first(condition)).delete_prefix("---\n")

  def self.field_first(node)
    case node
    when Hash then node.sort_by { |key, _| key == "field" ? 0 : 1 }.to_h { |key, value| [ key, field_first(value) ] }
    when Array then node.map { |item| field_first(item) }
    else node
    end
  end

  # A new rule's form, with the starter set's platform filled in.
  def self.blank = new(attributes: { "severity" => "medium", "platforms" => { "0" => { "distribution" => "debian", "versions" => "13" } }, "enabled" => "1" })

  # attributes: the submitted rule[...] parameters (strings, as a browser sends them); rule: the stored rule being
  # edited, or nil for a new one. A stored rule's key is its own, whatever was submitted.
  def initialize(attributes: {}, rule: nil)
    @rule = rule
    @problems = []
    attributes = attributes.to_h.stringify_keys
    TEXT_FIELDS.each { |name| instance_variable_set(:"@#{name}", text(attributes[name])) }
    @key = rule.key if rule
    @operator = OPERATORS.key?(attributes["operator"]) ? attributes["operator"] : "eq"
    @expected = text(attributes["expected"])
    @condition_text = attributes.key?("condition_text") ? text(attributes["condition_text"]) : nil
    @enabled = attributes["enabled"].to_s == "1"
    @platforms = platform_rows(attributes["platforms"])
  end

  def new_rule? = @rule.nil?

  def enabled? = @enabled

  # Whether the condition is edited as text (a stored rule whose condition is not one single comparison).
  def condition_as_text? = !@condition_text.nil?

  # The manifest's definition of the chosen fact, or nil.
  def fact_definition = ConfigManifest.current.fact(fact)

  # The facts the fact select offers: every one when the condition is text, else those a single comparison fits,
  # with the chosen one kept so the form shows what was stored or typed.
  def fact_choices
    facts = ConfigManifest.current.facts
    condition_as_text? ? facts : facts.select { |definition| SINGLE_TYPES.include?(definition.type) || definition.key == fact }
  end

  # The operators the select offers for the chosen fact: ordering only makes sense for an integer.
  def operator_choices
    type = fact_definition&.type
    return OPERATORS if type.nil? || type == "integer"

    OPERATORS.reject { |name, _| INTEGER_OPERATORS.include?(name) && name != operator }
  end

  # Whether the expected value is a number input: an integer fact compared with one number.
  def number_input? = fact_definition&.type == "integer" && !LIST_OPERATORS.include?(operator)

  # The rule as a rule file holds it. A new rule states its enabled flag; an edit leaves it out, so the stored
  # flag is kept (the edit page does not change it).
  def to_rule
    @local_problems = []
    rule = { "key" => key, "reference" => reference, "title" => title, "severity" => severity, "applies_to" => applies_to,
             "fact" => fact, "condition" => condition, "remediation" => remediation }
    rule["enabled"] = enabled? if new_rule?
    rule
  end

  # Runs the import's checks on to_rule. Returns true when the rule is valid (rule is then what was checked);
  # otherwise problems lists every one.
  def valid?
    @rule_hash = to_rule
    checked = CisRules::RuleFile.parse_rule(@rule_hash)
    found = checked.problems
    found = found.reject { |problem| problem.pointer.start_with?("/condition") } if @local_problems.any?
    @problems = (found + @local_problems).map { |problem| place(problem) }
    if new_rule? && @problems.none? { |problem| problem.field == "key" } && CisRule.exists?(key:)
      @problems << Problem.new(field: "key", pointer: "/key", message: "#{key} is already used by another rule; a key is never reused")
    end
    @problems.empty?
  end

  # Adds a problem found when saving (the key was taken, the rule changed) to show like the others.
  def add_problem(field, message) = @problems << Problem.new(field:, pointer: field == "base" ? "/" : "/#{field}", message:)

  def problems_for(field) = problems.select { |problem| problem.field == field }

  def invalid?(field) = problems_for(field).any?

  # The hidden form fields that carry what was typed through the preview, so Save saves exactly what was previewed.
  def to_params
    params = TEXT_FIELDS.to_h { |name| [ name, public_send(name).to_s ] }
    params["platforms"] = platforms.each_with_index.to_h { |platform, i| [ i.to_s, { "distribution" => platform.distribution, "versions" => platform.versions } ] }
    if condition_as_text?
      params["condition_text"] = condition_text
    else
      params["operator"] = operator
      params["expected"] = expected
    end
    params["enabled"] = enabled? ? "1" : "0" if new_rule?
    params
  end

  private

  def text(value) = value.is_a?(String) ? value : ""

  def platform_rows(value)
    rows = value.respond_to?(:to_h) ? value.to_h.sort_by { |index, _| index.to_s.to_i }.map(&:last) : []
    rows = rows.select { |row| row.respond_to?(:to_h) }.map(&:to_h).map(&:stringify_keys).first(MAX_PLATFORMS)
    rows = rows.map { |row| Platform.new(distribution: text(row["distribution"]).strip, versions: text(row["versions"]).strip) }
    rows.reject { |row| row.distribution.empty? && row.versions.empty? }
  end

  def load_version(version)
    @key = @rule.key
    @title, @reference, @severity, @fact, @remediation = version.title, version.reference, version.severity, version.fact, version.remediation
    @platforms = version.applies_to.map { |platform| Platform.new(distribution: platform["distribution"], versions: Array(platform["versions"]).join(", ")) }
    single = single_comparison(version.condition)
    if single
      @operator, @expected = single
    else
      @condition_text = self.class.condition_yaml(version.condition)
    end
  end

  # [operator, expected text] when the condition is one comparison the form shows exactly (reading the text back
  # gives the same operand), else nil.
  def single_comparison(condition)
    return nil unless SINGLE_TYPES.include?(fact_definition&.type) && condition.is_a?(Hash) && condition.size == 1

    name, operand = condition.first
    return nil unless OPERATORS.key?(name)

    shown = operand.is_a?(Array) ? operand.map { |item| item.is_a?(String) ? item : JSON.generate(item) }.join(", ") : operand.to_s
    @operator = name
    operand_from(shown) == operand ? [ name, shown ] : nil
  end

  def applies_to
    platforms.map do |platform|
      versions = platform.versions.split(",").map(&:strip).reject(&:empty?)
      versions.empty? ? { "distribution" => platform.distribution } : { "distribution" => platform.distribution, "versions" => versions }
    end
  end

  def condition
    return { operator => operand_from(expected) } unless condition_as_text?
    return local_problem("/condition", "is longer than #{CONDITION_TEXT_MAX / 1.kilobyte} KiB") if condition_text.bytesize > CONDITION_TEXT_MAX
    return local_problem("/condition", "is required") if condition_text.strip.empty?

    YAML.safe_load(condition_text, permitted_classes: [], aliases: false)
  rescue Psych::Exception => e
    local_problem("/condition", "is not plain YAML or JSON (#{e.message.truncate(200)})")
  end

  def local_problem(pointer, message)
    @local_problems << CisRules::RuleFile::Problem.new(pointer:, message:)
    nil
  end

  # The expected value as the fact's type reads it. A value that does not fit is kept as text, so the import's
  # checks name the problem ("lte needs an integer").
  def operand_from(value)
    type = fact_definition&.type
    if LIST_OPERATORS.include?(operator) || (type == "string_list" && %w[eq ne].include?(operator))
      item_type = type == "string_list" ? "string" : type
      value.split(",").map(&:strip).reject(&:empty?).map { |item| scalar(item, item_type) }
    else
      scalar(value, type)
    end
  end

  def scalar(value, type)
    case type
    when "integer" then value.strip.match?(/\A[+-]?\d{1,16}\z/) ? Integer(value.strip, 10) : value
    when "boolean" then boolean(value)
    else value
    end
  end

  def boolean(value)
    word = value.strip.downcase
    return true if TRUE_WORDS.include?(word)
    return false if FALSE_WORDS.include?(word)

    value
  end

  # A problem from the checks, beside its field, in words the form can show: the schema's "string length at
  # `/rules/0/title` is less than: 1" becomes "is required".
  def place(problem)
    field = problem.pointer.split("/")[1].to_s
    field = "base" unless FIELD_LABELS.key?(field)
    message = problem.message.gsub(%r{ at `/rules/0[^`]*`}, "")
    message = "is required" if message.match?(/\A(string length|array size) is less than: 1\z/)
    Problem.new(field:, pointer: problem.pointer, message:)
  end
end
