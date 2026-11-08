# Display helpers for the Configuration tab and the snapshot comparison (P2-D02, approved mockups host-config.html,
# host-config-diff.html, states-host.html). Every fact value, reason, and observed value comes from an agent and
# passes through Rails' escaping; nothing here marks it safe. Results and states are words as well as lamp shapes.
module HostConfigsHelper
  RESULTS = {
    "pass" => [ "Pass", "online" ], "fail" => [ "Fail", "fail" ], "not_readable" => [ "Not readable", "stale" ],
    "not_applicable" => [ "Not applicable", "na" ], "not_evaluated" => [ "Not evaluated", "awaiting" ]
  }.freeze
  FACT_STATES = { "ok" => [ "OK", "online" ], "unreadable" => [ "Unreadable", "stale" ], "unsupported" => [ "Unsupported", "unsup" ], "missing" => [ "Missing", "awaiting" ] }.freeze
  RESULT_CHIPS = { "attention" => "Needs attention", "fail" => "Fail", "not_readable" => "Not readable", "pass" => "Pass",
                   "not_applicable" => "Not applicable", "not_evaluated" => "Not evaluated", "all" => "All" }.freeze
  TRUNCATED = /… \(truncated from [\d,]+ bytes\)\z/
  LONG_VALUE = 120 # characters of JSON past which an observed value gets a scrolling box

  # JSON for display: unlike to_json, it leaves < > & as they are, so the page escapes them as text once.
  def json(value) = JSON.generate(value)

  def result_lamp(result)
    word, lamp = RESULTS.fetch(result)
    tag.span(word, class: [ "lamp", lamp ])
  end

  def fact_state_lamp(state)
    word, lamp = FACT_STATES.fetch(state) { [ state.to_s.humanize, "awaiting" ] }
    tag.span(word, class: [ "lamp", lamp ])
  end

  # "108 OK, 2 unreadable, 1 unsupported, and 1 missing".
  def fact_state_counts(counts)
    AgentApi::ConfigReport::STATES.map { |state| "#{counts.fetch(state, 0)} #{state == 'ok' ? 'OK' : state}" }.to_sentence
  end

  def severity_tag(severity) = tag.span(severity.to_s.capitalize, class: [ "sev", severity ])

  # A fact's value as the manifest types it: strings quoted, lists one entry per line, a file's or unit's parts in
  # words, and a file or unit that does not exist said so.
  def fact_value(key, value, definition = ConfigManifest.current.fact(key))
    case definition&.type
    when "file_attributes"
      value.nil? ? tag.span("File does not exist", class: "val unavailable") : tag.span("mode #{value['mode']}, owner #{value['owner']}, group #{value['group']}", class: "val")
    when "service_state"
      value.nil? ? tag.span("Not installed", class: "val unavailable") : tag.span("#{value['active']}, #{value['enabled']}", class: "val")
    when "string_list"
      list_value(value, ordered: definition.constraints["ordered"])
    else
      tag.span(json(value), class: "val")
    end
  end

  def list_value(value, ordered:)
    entries = Array(value)
    note = "#{pluralize(entries.size, 'entry')}#{', order matters' if ordered}"
    return tag.span(note, class: "state-note") if entries.empty?

    safe_join([ tag.span(safe_join(entries.map { |entry| json(entry) }, tag.br), class: "val list"), tag.span(note, class: "state-note") ])
  end

  # An observed value as stored (JSON, cut at 1 KiB by the evaluator): short ones inline, long ones in a box that
  # scrolls and takes focus, a cut one said so in words.
  def observed_value(observed, fact)
    truncated = observed.is_a?(String) && observed.match?(TRUNCATED)
    text = truncated ? observed : json(observed)
    return tag.span(text, class: "val") if text.length <= LONG_VALUE && !truncated

    label = truncated ? "Observed value, cut at 1 KiB" : "Observed value"
    parts = [ tag.pre(text, class: "value", tabindex: 0, "aria-label": label) ]
    parts << tag.span(safe_join([ "Cut at 1 KiB. The whole value is in the ", link_to("facts", "#facts"), " as ", tag.code(fact), "." ]), class: "trunc") if truncated
    safe_join(parts)
  end

  # A rule condition in words: "equals false", "at most 4", "mode at most 0640, owner equals \"root\"".
  def expected_words(node, fact_type = nil)
    return node.map { |child| expected_words(child, fact_type) }.join(", ") if node.is_a?(Array)
    return node["all"].map { |child| expected_words(child, fact_type) }.join(", ") if node.key?("all")
    return node["any"].map { |child| expected_words(child, fact_type) }.join(" or ") if node.key?("any")
    return "not (#{expected_words(node['not'], fact_type)})" if node.key?("not")

    name = CisRules::Condition.operator(node)
    words = operator_words(name, node[name], node["field"] ? "string" : fact_type)
    node["field"] ? "#{node['field']} #{words}" : words
  end

  def operator_words(name, operand, type)
    list = type == "string_list"
    operands = -> { Array(operand).map { |entry| json(entry) }.join(", ") }
    case name
    when "eq" then "equals #{json(operand)}"
    when "ne" then "does not equal #{json(operand)}"
    when "in" then list ? "contains only #{operands.call}" : "is one of #{operands.call}"
    when "not_in" then list ? "contains none of #{operands.call}" : "is none of #{operands.call}"
    when "gte" then "at least #{operand}"
    when "lte" then "at most #{operand}"
    when "matches" then list ? "every entry matches #{json(operand)}" : "matches #{json(operand)}"
    when "mode_at_most" then "mode at most #{operand}"
    when "present" then type == "service_state" ? "is installed" : "exists"
    else type == "service_state" ? "is not installed" : "does not exist" # absent
    end
  end

  # Why a check is not readable, not applicable, or not evaluated. A not readable reason names the fact it comes
  # from, so the reason in the facts list reads the same in every check that depends on it (AC-2.5).
  def check_reason(check)
    reason = check.reason.to_s
    return reason unless check.result == "not_readable" && !reason.start_with?("The host has not reported its operating system")

    "#{check.version.fact}: #{reason}"
  end

  # The current URL with some parameters changed (nil removes one), for filter chips and "show all" links.
  def with_params(**changes)
    query = request.query_parameters.merge(changes.stringify_keys).compact_blank
    query.empty? ? request.path : "#{request.path}?#{query.to_query}"
  end

  # "2026-11-06 09:14 UTC (latest, 3 facts changed)" for a snapshot picker.
  def snapshot_option_label(snapshot, changed, latest, first)
    notes = [ ("latest" if latest), (first ? "oldest kept" : ("#{pluralize(changed, 'fact')} changed" if changed)) ].compact
    notes.empty? ? utc(snapshot.received_at) : "#{utc(snapshot.received_at)} (#{notes.join(', ')})"
  end

  # "Fail → Pass" as two lamps.
  def result_flip(from, to) = safe_join([ result_lamp(from), " → ", result_lamp(to) ])

  # What caused a change of result, in words (CisResultHistory).
  def change_cause(entry)
    case entry.cause
    when :first then "First result for this check"
    when :report then report_cause(entry)
    when :rule_edited then safe_join([ tag.strong("Rule edited"), " to version #{entry.version}#{" by #{entry.actor}" if entry.actor}; no new report" ])
    when :rule_enabled then safe_join([ tag.strong("Rule enabled"), (" by #{entry.actor}" if entry.actor).to_s, "; no new report" ])
    when :rule_disabled then safe_join([ tag.strong("Rule disabled"), (" by #{entry.actor}" if entry.actor).to_s ])
    else "Re-evaluated with no new config report"
    end
  end

  def report_cause(entry)
    return "First config report" if entry.first_report
    return safe_join([ "New config report: ", tag.code(entry.fact), " added to the manifest" ]) if entry.before.nil?

    before, after = entry.before, entry.after
    detail = if before == after then " unchanged"
    elsif before["state"] != after["state"] && after["state"] != "ok" then " became #{FACT_STATES.dig(after['state'], 0).to_s.downcase}"
    elsif before["state"] != after["state"] then " became readable: #{json(after['value'])}"
    else " #{json(before['value'])} → #{json(after['value'])}"
    end
    safe_join([ "New config report: ", tag.code(entry.fact), detail ])
  end

  # The request box's texts for the Configuration tab (P2-D02, Q6, Q7): the last report, what the button does, and
  # what an answered request did. Built here rather than in the view, as for the Packages tab (review of #124).
  def config_request_texts(host, config, latest_snapshot, answered_new_snapshot:)
    ready = if config
      safe_join([ tag.strong("Config report received #{seen_ago(config.received_at).downcase_first}."),
                  " Collected #{utc(config.collected_at)}#{" by agent #{host.agent_version}" if host.agent_version}, manifest version #{config.manifest_version}.",
                  (" Facts unchanged since snapshot #{utc(latest_snapshot.received_at)}." if latest_snapshot) ].compact)
    else
      tag.strong("No config report yet.")
    end
    { ready:,
      ready_hint: "Config reports arrive every 6 hours, or when you ask. Each report type can be requested once every #{ReportRequests::COOLDOWN.in_minutes.to_i} minutes; " \
                  "an unanswered request expires after #{ReportRequests::TTL.in_minutes.to_i} minutes.",
      answered_hint: answered_new_snapshot ? "The new report changed some facts, so a new snapshot was recorded." : "The new report showed no change, so no new snapshot was recorded. That still answers the request." }
  end
end
