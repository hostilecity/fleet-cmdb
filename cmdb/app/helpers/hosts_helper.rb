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
end
