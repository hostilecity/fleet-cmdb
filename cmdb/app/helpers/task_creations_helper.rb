# Words for the create-task flow (P3-S08, mockups create-*.html): why a host is left out, what a refused request
# got wrong, and the hidden fields that carry earlier choices from step to step.
module TaskCreationsHelper
  STEPS = [ "Task type", "Parameters", "Targets", "Confirm" ].freeze

  # Where a problem's JSON Pointer points, in words, for "The service is not on the allowlist."
  PROBLEM_SUBJECTS = {
    "" => "The request", "/type" => "The task type", "/parameters" => "The parameters", "/parameters/service" => "The service",
    "/target" => "The selection", "/target/host_ids" => "The selection", "/target/tag" => "The tag",
    "/confirm_host_count" => "The number typed", "/confirmation" => "The confirmation", "/second_factor_code" => "The second factor"
  }.freeze

  # The step list at the top of each page, with the earlier steps as links back.
  def task_flow(current, links = {})
    items = STEPS.each_with_index.map do |label, index|
      step = index + 1
      content = tag.span(label, class: "lbl")
      if step < current
        tag.li(links[step] ? link_to(content, links[step]) : content, class: "done")
      else
        tag.li(content, "aria-current": ("step" if step == current))
      end
    end
    tag.ol(safe_join(items), class: "flow", "aria-label": "New task: step #{current} of #{STEPS.size}")
  end

  # The request so far as query parameters: type, parameters, and target, for links back to an earlier step.
  def task_request_query(type:, parameters: nil, target: nil)
    { type:, parameters: parameters.presence, target: target.presence }.compact
  end

  # Hidden fields for the parts of the request already chosen, in the shape the next step reads.
  def task_request_fields(type: nil, parameters: {}, target: nil)
    fields = []
    fields << hidden_field_tag(:type, type, id: nil) if type
    parameters.to_h.each { |name, value| fields << hidden_field_tag("parameters[#{name}]", value, id: nil) }
    if target.is_a?(Hash) && target["tag"]
      fields << hidden_field_tag("target[tag]", target["tag"], id: nil)
    elsif target.is_a?(Hash) && target["host_ids"].is_a?(Array)
      target["host_ids"].each { |id| fields << hidden_field_tag("target[host_ids][]", id, id: nil) }
    end
    safe_join(fields)
  end

  # A problem as a sentence: "The service is not on the server's restart allowlist."
  def task_problem_sentence(problem)
    pointer = problem["pointer"].to_s
    subject = PROBLEM_SUBJECTS[pointer] ||
              if pointer.start_with?("/parameters/") then "The parameter #{pointer.delete_prefix('/parameters/')}"
              elsif pointer.start_with?("/target/host_ids/") then "Host #{pointer.split('/').last.to_i + 1} in the selection"
              else "The field #{pointer.delete_prefix('/').gsub('~1', '/').gsub('~0', '~')}"
              end
    "#{subject} #{problem['problem']}."
  end

  # Why a host is left out, as a headline and a sentence (create-targets.html#excluded).
  def task_exclusion_text(reason, host, entry, parameters, allowlist)
    service = parameters["service"]
    case reason
    when "not_active"
      [ "Not active.", "#{host_state_words(host)} Only active hosts get tasks." ]
    when "machine_id_mismatch"
      [ "Credential in use on another machine.", "Its credential was last used from a different machine, so no task is sent to it until that is resolved on the host page." ]
    when "no_capability_report"
      [ "Agent does not support tasks.", "Agent #{host.agent_version || 'of unknown version'} has not reported which tasks it runs. Tasks need an agent that does (Agents)." ]
    when "not_supported"
      [ "Agent does not support this task.", "Agent #{host.agent_version || 'of unknown version'} does not run #{entry.type}. A newer agent may (Agents)." ]
    when "not_enabled"
      [ "Not enabled on this VM.", "Its agent reports that #{entry.type} is not enabled in its configuration. Enabling it is an edit on the VM itself." ]
    when "not_allowed_on_server"
      tags = allowlist.select { |item| item.service == service }.filter_map(&:tag)
      [ "Service not allowed for this host.", "#{service} is allowed only on hosts tagged #{tags.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')}." ]
    when "not_allowed_locally"
      [ "Not in this VM's own allowlist.", "Its agent does not list #{service} in its own allowlist, so it would refuse the task." ]
    end
  end

  # The short form, for the picking table and the confirmation: "not enabled on this VM".
  def task_exclusion_short(reason, host)
    {
      "not_active" => "not active (#{host_state_words(host).delete_suffix('.').downcase_first})", "machine_id_mismatch" => "credential in use on another machine",
      "no_capability_report" => "agent does not support tasks", "not_supported" => "agent does not support this task", "not_enabled" => "not enabled on this VM",
      "not_allowed_on_server" => "service not allowed for this host", "not_allowed_locally" => "not in this VM's own allowlist"
    }.fetch(reason)
  end

  # Q8: an offline or stale host stays in the batch, with a warning.
  def task_liveness_warning(host, expiry)
    return unless host.enrollment_state == "active" && host.liveness_status.in?(%w[offline stale])

    "Last seen #{seen_ago(host.last_seen_at)}. Its task waits for it and expires after #{human_duration(expiry.to_i)} if it does not ask for it."
  end

  # The catalog's time limit and expiry in words: "5 minutes", "24 hours".
  def task_duration(duration) = human_duration(duration.to_i)

  private

  def host_state_words(host)
    case host.enrollment_state
    when "revoked" then "Its credential was revoked."
    when "retired" then "It is retired."
    else "It has not enrolled yet."
    end
  end
end
