# Display helpers for audit entries: the audit log page (P1-AUDIT-PAGE) and the host page's audit section
# (P1-D03). Every recorded value is operator or agent input, so all of it goes through Rails' escaping;
# nothing here marks a recorded value as safe.
module AuditEntriesHelper
  AUDIT_LABELS = {
    Audit::Actions::HOST_CREATED => "Host created",
    Audit::Actions::HOST_EDITED => "Host edited",
    Audit::Actions::HOST_ENROLLED => "Enrolled",
    Audit::Actions::HOST_CREDENTIAL_REVOKED => "Credential revoked",
    Audit::Actions::HOST_REENROLLMENT_STARTED => "Re-enrollment started",
    Audit::Actions::HOST_RETIRED => "Retired",
    Audit::Actions::HOST_ENROLLMENT_TOKEN_ISSUED => "Enrollment token issued",
    Audit::Actions::HOST_FIRST_INVENTORY => "First inventory received",
    Audit::Actions::HOST_MACHINE_ID_MISMATCH => "Credential used from another machine",
    Audit::Actions::HOST_REPORT_REQUESTED => "Fresh reports requested",
    Audit::Actions::ONBOARDING_APPROVED => "Onboarding approved",
    Audit::Actions::ONBOARDING_REJECTED => "Onboarding rejected",
    Audit::Actions::OPERATOR_ALLOWED => "Operator allowed",
    Audit::Actions::OPERATOR_DISALLOWED => "Operator removed",
    Audit::Actions::OPERATOR_SIGNED_IN => "Operator signed in",
    Audit::Actions::RELEASE_IMPORTED => "Release imported",
    Audit::Actions::RELEASE_IMPORT_REFUSED => "Release refused",
    Audit::Actions::RELEASE_IMPORT_FAILED => "Release import failed",
    Audit::Actions::ROLLOUT_STARTED => "Rollout started",
    Audit::Actions::ROLLOUT_ADVANCED => "Rollout advanced",
    Audit::Actions::ROLLOUT_HALTED => "Rollout halted",
    Audit::Actions::ROLLOUT_RESUMED => "Rollout resumed",
    Audit::Actions::ROLLOUT_CANCELLED => "Rollout cancelled",
    Audit::Actions::ROLLOUT_COMPLETED => "Rollout completed",
    Audit::Actions::UPDATE_REQUESTED => "Agent update requested",
    Audit::Actions::UPDATE_SUCCEEDED => "Agent update succeeded",
    Audit::Actions::UPDATE_FAILED => "Agent update failed",
    Audit::Actions::UPDATE_ROLLED_BACK => "Agent update rolled back",
    Audit::Actions::UPDATE_UNCONFIRMED => "Agent update unconfirmed",
    Audit::Actions::SETTING_CHANGED => "Setting changed",
    Audit::Actions::RULE_CREATED => "Rule created",
    Audit::Actions::RULE_EDITED => "Rule edited",
    Audit::Actions::RULE_ENABLED => "Rule enabled",
    Audit::Actions::RULE_DISABLED => "Rule disabled",
    Audit::Actions::ADVISORY_IMPORTED => "Advisories imported",
    Audit::Actions::ADVISORY_IMPORT_FAILED => "Advisory import failed",
    Audit::Actions::ADVISORY_REFRESH_REQUESTED => "Advisory refresh started",
    Audit::Actions::ADVISORY_REFRESH_REFUSED => "Advisory refresh refused (cool-down)",
    Audit::Actions::ADVISORY_UPLOADED => "Advisory file uploaded",
    Audit::Actions::ADVISORY_WITHDRAWALS_CONFIRMED => "Advisory withdrawals confirmed (full import)"
  }.freeze

  # Groups for the action filter, by the part before the dot. Actions added later group themselves.
  AUDIT_GROUPS = { "host" => "Hosts", "onboarding" => "Onboarding", "operator" => "Operators", "release" => "Agent releases", "rollout" => "Rollouts", "update" => "Agent updates", "setting" => "Settings", "rule" => "CIS-aligned rules", "advisory" => "Advisory data" }.freeze

  SETTING_NAMES = { "liveness.online_threshold_minutes" => "Online threshold", "liveness.stale_threshold_minutes" => "Stale threshold" }.freeze
  INTERVAL_SETTING_NAMES = { "agent.heartbeat_seconds" => "Agent heartbeat interval", "agent.inventory_seconds" => "Agent inventory interval" }.freeze

  # Recorded field => [label, monospace]. Shown in this order; fields not listed follow, named as recorded.
  AUDIT_FIELDS = {
    "name" => [ "Name", false ],
    "hostname" => [ "Hostname", true ],
    "tags" => [ "Tags", true ],
    "description" => [ "Description", false ],
    "notes" => [ "Notes", false ],
    "enrollment_state" => [ "Enrollment state", true ],
    "key_id" => [ "Key", true ],
    "revoked_key_id" => [ "Revoked key", true ],
    "onboarding_request_id" => [ "Onboarding request", true ],
    "expires_at" => [ "Token expires", true ],
    "stable_hash" => [ "Inventory fingerprint", true ],
    "machine_id" => [ "Machine ID", true ],
    "state" => [ "State", true ],
    "reenroll" => [ "Re-enroll", true ],
    "report_types" => [ "Report types", true ],
    "host_id" => [ "Host", false ],
    "email" => [ "Email", false ],
    "version" => [ "Version", true ],
    "source" => [ "Source", false ],
    "reason" => [ "Reason", false ],
    "sha256" => [ "SHA-256", true ],
    "size" => [ "Size (bytes)", true ],
    "key_role" => [ "Release key", false ],
    "title" => [ "Title", false ],
    "reference" => [ "Reference", false ],
    "severity" => [ "Severity", true ],
    "applies_to" => [ "Applies to", true ],
    "fact" => [ "Fact", true ],
    "condition" => [ "Condition", true ],
    "remediation" => [ "Remediation", false ],
    "enabled" => [ "Enabled", true ],
    "origin" => [ "Origin", true ],
    "full" => [ "Full data set", false ],
    "ecosystems" => [ "Ecosystems", true ],
    "counts" => [ "Counts", true ],
    "next_allowed_at" => [ "Next refresh allowed", true ],
    **SETTING_NAMES.keys.index_with { [ "Minutes", true ] },
    **INTERVAL_SETTING_NAMES.keys.index_with { [ "Seconds", true ] }
  }.freeze

  # Recorded as ISO 8601 and shown like every other time on the page.
  TIME_FIELDS = %w[expires_at next_allowed_at].freeze

  # /audit with these query parameters. Built by hand because url_for treats an :action key as the route's
  # action, and the filter is called action.
  def audit_page_path(query = {})
    query = query.to_h.compact_blank
    query.empty? ? audit_path : "#{audit_path}?#{query.to_query}"
  end

  def audit_label(action) = AUDIT_LABELS.fetch(action) { action.to_s.tr("._", "  ").capitalize }

  def audit_action_options(selected)
    rank = ->(list, key) { [ list.index(key) || list.size, key ] }
    actions = Audit::Actions::ALL.sort_by { |action| rank.(AUDIT_LABELS.keys, action) }
    groups = actions.group_by { |action| action.split(".").first }.sort_by { |prefix, _| rank.(AUDIT_GROUPS.keys, prefix) }.map do |prefix, members|
      [ AUDIT_GROUPS.fetch(prefix) { prefix.humanize.pluralize }, members.map { |action| [ audit_label(action), action ] } ]
    end
    grouped_options_for_select(groups, selected)
  end

  def audit_time(time) = time.utc.strftime("%Y-%m-%d %H:%M:%S")

  def audit_actor(entry, records)
    case entry.actor_type
    when "operator"
      safe_join([ records.operators[entry.actor_id]&.email || "Operator #{entry.actor_id}", " ", tag.span("Operator", class: "kind") ])
    when "host"
      host = records.hosts[entry.actor_id]
      safe_join([ host ? link_to(host.name, host_path(host)) : "Host #{entry.actor_id}", " ", tag.span("Host", class: "kind") ])
    else
      "System"
    end
  end

  def audit_target(entry, records)
    id = entry.target_id
    case entry.target_type
    when "Host"
      host = records.hosts[id]
      return "Host #{id}" unless host

      safe_join([ link_to(host.name, host_path(host)), (tag.span("Retired host", class: "kind") if host.retired?) ].compact, " ")
    when "OnboardingRequest"
      hostname = records.requests[id]&.hostname
      host = records.hosts[records.request_hosts[id]]
      safe_join([ "Onboarding request #{id}", (tag.span(hostname, class: "kind mono") if hostname),
                  (tag.span(safe_join([ "Host ", link_to(host.name, host_path(host)) ]), class: "kind") if host) ].compact, " ")
    when "Operator" then records.operators[id]&.email || "Operator #{id}"
    when "AgentRelease" then link_to("Agent release #{Array(entry.changeset['version']).compact.last || id}", agents_path)
    when "AdvisoryImport" then link_to("Advisory import #{id}", advisory_import_path(id))
    when "CisRule" then safe_join([ "Rule", tag.span(records.rules[id] || id.to_s, class: "kind mono") ], " ")
    when "OperatorAllowlistEntry" then records.allowlist[id] || Array(entry.changeset["email"]).compact.first || "Allowlist entry #{id}"
    when "Setting"
      # A cleared interval deletes its row, so fall back to the key the entry recorded (it is the changeset's key).
      key = records.settings[id]
      key ||= (entry.changeset.keys & SETTING_NAMES.merge(INTERVAL_SETTING_NAMES).keys).first if entry.changeset.is_a?(Hash)
      key ? safe_join([ SETTING_NAMES.merge(INTERVAL_SETTING_NAMES).fetch(key, key), tag.span(key, class: "kind mono") ], " ") : "Setting #{id}"
    when nil then tag.span("None", class: "muted")
    else "#{entry.target_type} #{id}"
    end
  end

  # One line per recorded field: before struck out, after highlighted. A field recorded as a single value
  # (a revoked key, or a value the server filtered) is shown as recorded.
  def audit_changes(entry, records)
    changes = entry.changeset.is_a?(Hash) ? entry.changeset : {}
    changes = changes.reject { |_, value| value == [ nil, nil ] } # nothing to show (a new host's host_id)
    return tag.span("No values recorded", class: "muted") if changes.empty?

    order = AUDIT_FIELDS.keys
    items = changes.sort_by { |key, _| [ order.index(key) || order.size, key ] }.map do |key, value|
      label, mono = AUDIT_FIELDS.fetch(key) { [ key, true ] }
      tag.li(safe_join([ tag.span(label, class: [ "key", ("mono" unless AUDIT_FIELDS.key?(key)) ].compact), audit_change(key, value, mono, records) ], " "))
    end
    tag.ul(safe_join(items), class: "change-list")
  end

  # The filters in words, for the line above the results and the empty state.
  def audit_filter_summary(log)
    head = [ log.action ? tag.strong(audit_label(log.action)) : "All actions" ]
    head << safe_join([ " on ", tag.strong(log.target) ]) if log.target
    head << safe_join([ " on ", tag.strong(log.host ? log.host.name : "host #{log.host_id}"), (" (no such host)" unless log.host) ].compact) if log.host_id
    head << audit_actor_summary(log)
    tail = [ (tag.strong(audit_date_range(log.from, log.to)) if log.from || log.to), ("sign-ins hidden" if log.hide_sign_ins?) ].compact
    safe_join([ safe_join(head.compact), *tail.map { |part| safe_join([ ", ", part ]) } ])
  end

  # "1 to 28 Oct 2026", "28 Sep to 3 Oct 2026", "from 1 Oct 2026", "up to 28 Oct 2026". Whole UTC days.
  def audit_date_range(from, to)
    return "from #{from.strftime('%-d %b %Y')}" unless to
    return "up to #{to.strftime('%-d %b %Y')}" unless from

    start = if from.year != to.year then "%-d %b %Y"
    elsif from.month != to.month then "%-d %b"
    else "%-d"
    end
    "#{from.strftime(start)} to #{to.strftime('%-d %b %Y')}"
  end

  private

  def audit_actor_summary(log)
    kind = AuditLog::ACTOR_TYPES[log.actor_type]&.downcase
    if log.actor
      safe_join([ " by ", tag.strong(log.actor), (" (#{kind})" if kind) ].compact)
    elsif log.actor_type == "system"
      " by the system"
    elsif kind
      " by any #{kind}"
    end
  end

  def audit_change(key, value, mono, records)
    return audit_value(:span, key, value, mono, records) unless value.is_a?(Array) && value.size == 2

    before, after = value
    if before.nil?
      audit_value(:ins, key, after, mono, records)
    elsif after.nil?
      safe_join([ audit_value(:del, key, before, mono, records), " ", tag.span("none", class: "unavailable") ])
    else
      safe_join([ audit_value(:del, key, before, mono, records), " ", audit_value(:ins, key, after, mono, records) ])
    end
  end

  def audit_value(tag_name, key, value, mono, records)
    host = key == "host_id" && value.is_a?(Integer) ? records.hosts[value] : nil
    content = host ? link_to(host.name, host_path(host)) : audit_text(key, value)
    content_tag(tag_name, content, class: ("mono" if mono || !AUDIT_FIELDS.key?(key)))
  end

  def audit_text(key, value)
    case value
    when nil then "none"
    when true then "yes"
    when false then "no"
    when Array then value.map { |item| audit_text(key, item) }.join(", ")
    when Hash then value.to_json
    else TIME_FIELDS.include?(key) ? audit_recorded_time(value.to_s) : value.to_s
    end
  end

  def audit_recorded_time(text)
    audit_time(Time.iso8601(text))
  rescue ArgumentError
    text
  end
end
