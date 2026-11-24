# Display helpers for the host detail page (P1-D03). Every value passes through Rails' escaping; nothing
# here marks agent-supplied text as safe.
module HostsHelper
  # The agent's warning for a field it could not read, if any (FR-1.3).
  def inventory_warning(warnings, field)
    Array(warnings).find { |w| w["field"] == field || w["field"].to_s.start_with?("#{field}.", "#{field}/") }&.fetch("message", nil)
  end

  # A <dd> for an inventory fact: the value, or "Not available" with the agent's warning.
  def inventory_fact(value, warnings, field, mono: false)
    if value.nil? || value == ""
      tag.dd(class: "unavailable") do
        safe_join([ "Not available", (tag.span(inventory_warning(warnings, field), class: "why") if inventory_warning(warnings, field)) ].compact)
      end
    else
      tag.dd(value, class: ("mono" if mono))
    end
  end

  def unavailable(text = "Not available") = tag.span(text, class: "unavailable")

  def change_value(value)
    value.nil? ? unavailable : tag.span(value, class: "mono")
  end

  # How the agent process before the running one stopped (#251), in words, from what systemd told the unit's
  # ExecStopPost=. systemd's result for a kill at MemoryMax is oom-kill, or signal (status KILL) when it saw the
  # process exit before the cgroup's OOM event, so a SIGKILL says it may have been the memory limit. nil without a
  # record.
  def agent_last_stop_words(host)
    result = host.agent_last_stop_result
    return if result.nil?

    code = host.agent_last_stop_exit_code
    status = host.agent_last_stop_exit_status
    exit = case code
    when "exited" then "exit status #{status}"
    when "killed", "dumped" then [ (code == "dumped" ? "dumped core on" : "killed by"), status ? "signal #{status}#{' (SIGKILL)' if status == 9}" : "a signal" ].join(" ")
    end
    words = case result
    when "success" then "Stopped cleanly"
    when "oom-kill" then "Killed at its memory limit"
    when "signal" then status == 9 ? "Killed by SIGKILL, perhaps at its memory limit" : "Ended by a signal"
    when "exit-code" then "Exited with an error"
    else "Stopped"
    end
    "#{words} (systemd: #{[ result, exit ].compact.join(', ')})"
  end
end
