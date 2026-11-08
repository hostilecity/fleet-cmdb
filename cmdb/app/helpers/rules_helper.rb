# Display helpers for the rules pages (P2-D06, approved mockups docs/mockups/phase-2/rules*.html, rule*.html). Every
# title, reference, remediation, operand, file name, and problem is operator input or an agent's value and passes
# through Rails' escaping; nothing here marks it safe. Results and states are words as well as lamp shapes.
module RulesHelper
  FACT_TYPES = { "string" => "string", "integer" => "integer", "boolean" => "boolean", "string_list" => "list of strings",
                 "file_attributes" => "file attributes", "service_state" => "service state" }.freeze
  CHANGE_FIELDS = { "title" => "Title", "reference" => "Reference", "severity" => "Severity", "applies_to" => "Applies to", "fact" => "Fact",
                    "condition" => "Condition", "remediation" => "Remediation", "enabled" => "Enabled" }.freeze
  INLINE_MAX = 120 # characters of a remediation or title shown in a change before it is cut

  # "debian 13", "debian 12, 13", "ubuntu (every release)", joined with "; ".
  def platforms_text(applies_to)
    Array(applies_to).map { |platform| platform["versions"] ? "#{platform['distribution']} #{platform['versions'].join(', ')}" : "#{platform['distribution']} (every release)" }.join("; ")
  end

  # "integer, 0 to 1000", "list of strings", for a manifest fact; nil when the manifest does not have it.
  def fact_type_text(definition)
    return nil unless definition

    words = FACT_TYPES.fetch(definition.type, definition.type)
    limits = definition.constraints
    if definition.type == "integer" && limits["minimum"] > -ConfigManifest::SAFE_INTEGER && limits["maximum"] < ConfigManifest::SAFE_INTEGER
      "#{words}, #{limits['minimum']} to #{limits['maximum']}"
    else
      words
    end
  end

  def fact_option_label(definition) = "#{definition.key} (#{FACT_TYPES.fetch(definition.type, definition.type)})"

  # A rule's condition in words for its fact ("at most 4"), as the host Configuration tab says it.
  def rule_expected(version) = expected_words(version.condition, ConfigManifest.current.fact(version.fact)&.type)

  # The condition as YAML, the way a rule file writes it.
  def condition_yaml(condition) = RuleForm.condition_yaml(condition).chomp

  # A condition on one line, for a change list: "lte: 4", or YAML flow style for anything larger.
  def condition_inline(condition)
    return condition_yaml(condition) if condition.is_a?(Hash) && condition.size == 1 && !condition.values.first.is_a?(Enumerable)

    JSON.generate(condition)
  end

  # What one rule does across the fleet, for the list's "Fleet result" column (RuleList::Fleet).
  def fleet_result(row)
    fleet = row.fleet
    return tag.span("Not evaluated: rule disabled", class: "lamp awaiting") unless row.rule.enabled
    return tag.span("Not evaluated: no config report yet", class: "lamp awaiting") if fleet.evaluated.zero?

    of = "of #{pluralize(fleet.evaluated, 'host')}"
    parts = []
    parts << tag.span("Fails on #{fleet['fail']} #{of}", class: "lamp fail") if fleet["fail"].positive?
    parts << tag.span("Not readable on #{fleet['not_readable']} #{of}", class: "lamp stale") if fleet["not_readable"].positive?
    if parts.empty?
      parts << if fleet["pass"].zero? then tag.span("Not applicable on all #{pluralize(fleet.evaluated, 'host')}", class: "lamp na")
      elsif fleet["not_applicable"].zero? then tag.span("Passes on all #{pluralize(fleet['pass'], 'host')}", class: "lamp online")
      else tag.span("Passes on all #{pluralize(fleet['pass'], 'host')} it applies to", class: "lamp online")
      end
    end
    safe_join(parts, tag.br)
  end

  def rule_status_lamp(rule) = rule.enabled ? tag.span("Enabled", class: "lamp online") : tag.span("Disabled", class: "lamp na")

  # One recorded field of a rule change, before and after, in the mockups' words.
  def rule_change_item(name, before, after)
    label = CHANGE_FIELDS.fetch(name, name)
    mono = %w[condition applies_to fact].include?(name)
    show = ->(value) { rule_change_value(name, value) }
    tag.li(safe_join([ label, " ", tag.del(show.(before), class: ("mono" if mono)), " ", tag.ins(show.(after), class: ("mono" if mono)) ]))
  end

  def rule_change_value(name, value)
    case name
    when "condition" then condition_inline(value)
    when "applies_to" then platforms_text(value)
    when "enabled" then value ? "yes" : "no"
    else value.to_s.truncate(INLINE_MAX)
    end
  end

  # Where a rule change was made, as the change log says it (CisRule::SOURCES).
  SOURCE_WORDS = { "file_upload" => "from a rules file import", "dashboard" => "in the dashboard", "rules_import" => "by rules:import" }.freeze

  # The change log's description of one audit entry for a rule: "Created from a rules file import, version 1",
  # "Edited in the dashboard, version 1 → 2". An entry recorded before sources were has no source words.
  def rule_change_summary(entry)
    version = entry.changeset["version"]
    verb = { Audit::Actions::RULE_CREATED => "Created", Audit::Actions::RULE_EDITED => "Edited", Audit::Actions::RULE_ENABLED => "Enabled" }.fetch(entry.action, "Disabled")
    words = [ verb, SOURCE_WORDS[entry.changeset["source"]] ].compact.join(" ")
    case entry.action
    when Audit::Actions::RULE_CREATED then "#{words}, version #{Array(version).last}"
    when Audit::Actions::RULE_EDITED then "#{words}, version #{Array(version).first} → #{Array(version).last}"
    else words
    end
  end

  # The before and after values of one rule audit entry.
  def rule_change_details(entry)
    changes = entry.changeset.except("version", "source")
    if entry.action == Audit::Actions::RULE_CREATED
      return tag.span("All fields set, #{changes.dig('enabled', 1) == false ? 'disabled' : 'enabled'}", class: "muted")
    end

    items = changes.sort_by { |name, _| CHANGE_FIELDS.keys.index(name) || CHANGE_FIELDS.size }.map { |name, (before, after)| rule_change_item(name, before, after) }
    tag.ul(safe_join(items), class: "change-list")
  end

  # The operator or system that made an audit entry, by name.
  def rule_actor(entry, records)
    return "System" unless entry&.actor_type == "operator"

    operator = records.operators[entry.actor_id]
    operator ? operator.display_name : "Operator #{entry.actor_id}"
  end

  # "2026-11-06 09:14" (the pages say UTC in the column heading).
  def rule_time(time) = time&.utc&.strftime("%Y-%m-%d %H:%M")

  # The add and edit forms' problems at the top: a link to the field, its pointer when it says more, the message. A
  # problem with the rule as a whole has no field to link to.
  def rule_problem_line(problem)
    if problem.field == "base"
      return tag.li(safe_join([ (safe_join([ tag.code(problem.pointer), ": " ]) unless problem.pointer == "/"), problem.message ].compact))
    end

    pointer = safe_join([ tag.code(problem.pointer), " " ]) if problem.deep?
    tag.li(safe_join([ link_to(RuleForm::FIELD_LABELS.fetch(problem.field), "#rule_#{problem.field}"), ": ", pointer, problem.message ].compact))
  end

  # A field's problems beside it, each with its pointer when it says more than the field.
  def rule_field_errors(form, field)
    problems = form.problems_for(field)
    return nil if problems.empty?

    tag.p(safe_join(problems.map { |problem| safe_join([ (safe_join([ tag.code(problem.pointer), ": " ]) if problem.deep?), problem.message ].compact) }, tag.br),
          class: "error-text", id: "rule_#{field}_error")
  end

  # aria-describedby for a field: its error (when it has one) and its hint.
  def rule_described_by(form, field, hint: true) = [ ("rule_#{field}_error" if form.invalid?(field)), ("rule_#{field}_hint" if hint) ].compact.join(" ").presence

  # The rule's hidden form fields, as typed, for the preview page's Save and Back buttons.
  def rule_hidden_fields(form)
    fields = form.to_params.flat_map do |name, value|
      next [ [ "rule[#{name}]", value ] ] unless value.is_a?(Hash)

      value.flat_map { |index, row| row.map { |part, text| [ "rule[#{name}][#{index}][#{part}]", text ] } }
    end
    safe_join(fields.map { |name, value| hidden_field_tag(name, value, id: nil) })
  end

  # The hint under a single comparison's expected value, for the chosen fact's type.
  def expected_value_hint(form)
    lists = "For one of and not one of, separate the values with commas."
    text = case form.fact_definition&.type
    when "integer" then "An integer, because the fact is an integer. #{lists}"
    when "boolean" then "true or false (yes and no work too), because the fact is a boolean."
    when "string" then "Text, compared exactly. #{lists}"
    when "string_list" then "Entries separated by commas, because the fact is a list."
    else "Must fit the fact's type."
    end
    form.new_rule? ? "#{text} A rule with several conditions can be added by importing a file." : text
  end

  # "The file is valid: 2 to add, 3 to change, 1 to enable, 33 unchanged."
  def rule_import_summary(plan)
    parts = [ ("#{plan.added.size} to add" if plan.added.any?), ("#{plan.changed.size} to change" if plan.changed.any?),
              ("#{plan.enabling.size} to enable" if plan.enabling.any?), ("#{plan.disabling.size} to disable" if plan.disabling.any?),
              "#{plan.unchanged.size} unchanged" ].compact
    "The file is valid: #{parts.join(', ')}."
  end

  # "38 of 41 hosts" style host counts for the previews.
  def hosts_count(count) = pluralize(count, "host")

  # Hosts a new or edited rule would not apply to, as the preview says it: "2 hosts are not debian 13".
  def not_applicable_words(count, applies_to)
    "#{count == 1 ? '1 host is' : "#{count} hosts are"} not #{Array(applies_to).map { |platform| platform['versions'] ? "#{platform['distribution']} #{platform['versions'].join(' or ')}" : platform['distribution'] }.join(' or ')}"
  end
end
