module ApplicationHelper
  LAMP_CLASSES = { "online" => "online", "stale" => "stale", "offline" => "offline", "awaiting" => "awaiting", "pending" => "pending", "revoked" => "revoked" }.freeze

  # A status lamp with its word: colour is never the only signal.
  def status_lamp(host)
    key = FleetList.status_of(host)
    tag.span(FleetList::STATUSES.fetch(key, key.humanize), class: [ "lamp", LAMP_CLASSES[key] ])
  end

  # "28 seconds ago", or "Never".
  def seen_ago(time)
    time ? "#{time_ago_in_words(time, include_seconds: true)} ago" : "Never"
  end

  def utc(time)
    time&.utc&.strftime("%Y-%m-%d %H:%M UTC")
  end

  def human_bytes(bytes) = ByteSize.format(bytes)

  # 90061 -> "1 day, 1 hour".
  def human_duration(seconds)
    return nil if seconds.nil?

    parts = ActiveSupport::Duration.build(seconds).parts.slice(:years, :months, :weeks, :days, :hours, :minutes).reject { |_, v| v.zero? }.first(2)
    parts.empty? ? "under a minute" : parts.map { |unit, value| pluralize(value, unit.to_s.singularize) }.join(", ")
  end

  # A bar that fills to the free or available share (mockups: P1-D01).
  def share_meter(part, whole, title)
    return "" unless part && whole&.positive?

    # Width classes in 5% steps rather than an inline style, so the CSP can forbid inline styles.
    step = ((100.0 * part / whole).clamp(0, 100) / 5).round * 5
    tag.span(tag.span(class: "w-#{step}"), class: "meter", title:, "aria-hidden": "true")
  end

  # A labelled form field with its errors shown in place (FR-S.4): the input is marked aria-invalid and
  # described by its error and hint. kind is :text_field or :text_area; value overrides the model's value.
  def form_field(form, attribute, label:, hint: nil, kind: :text_field, value: :model, **options)
    errors = form.object&.errors&.full_messages_for(attribute) || []
    base = "#{form.object_name}_#{attribute}"
    described = [ (errors.any? ? "#{base}_error" : nil), (hint ? "#{base}_hint" : nil) ].compact.join(" ").presence
    input_options = options.merge("aria-invalid": (errors.any? ? "true" : nil), "aria-describedby": described)
    input_options[:value] = value unless value == :model || kind == :text_area
    input = kind == :text_area && value != :model ? form.text_area(attribute, input_options.merge(value:)) : form.public_send(kind, attribute, input_options)
    tag.div(class: [ "field", ("invalid" if errors.any?) ]) do
      safe_join([
        form.label(attribute, label),
        input,
        (tag.p(errors.to_sentence, class: "error-text", id: "#{base}_error") if errors.any?),
        (tag.p(hint, class: "hint", id: "#{base}_hint") if hint)
      ].compact)
    end
  end
end
