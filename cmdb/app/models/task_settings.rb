# The server's task settings (P3-S06, DEC-14, DEC-15; mockup settings-tasks.html, owner decisions Q31 to Q33): the
# restart allowlist and the task limits. Every change goes through here, so each is validated, serialised with the
# others (one advisory lock), and audited with the values before and after, the operator as actor. The dashboard
# asks for the second factor before it calls these (TaskSettingsController, change_task_settings).
#
# - The allowlist (TaskAllowedService) starts empty: the restart task is then refused everywhere (ADR 0015). An
#   entry is a full .service name for every host or for one tag. Protected services (TaskPolicy::PROTECTED_SERVICES)
#   are refused, with no override (Q32).
# - The limits: hosts per batch (1 to 25, the hard cap of DEC-14), output kept per task (4 KiB to 1 MiB), the poll
#   interval hint sent to agents (10 to 300 seconds), and each task type's expiry (1 hour to 7 days, default the
#   catalog's 24 hours). They apply to what happens after the change: tasks already queued keep their expiry.
module TaskSettings
  # errors: { field => message }, for the form to mark each field ("service", "tag", "max_hosts_per_batch",
  # "expiry_hours.restart_service", ...).
  class Invalid < StandardError
    attr_reader :errors

    def initialize(errors)
      @errors = errors
      super(errors.values.join(" "))
    end
  end

  LOCK_KEY = "task_settings".freeze
  # At most this many allowlist entries, as the agent's own list (P3-A01).
  MAX_SERVICES = 64

  # field => [Setting key, label, unit]. Labels as the page names them (settings-tasks.html).
  LIMITS = {
    "max_hosts_per_batch" => [ "tasks.max_hosts_per_batch", "Most hosts in one batch", nil ],
    "output_limit_kib" => [ "tasks.output_limit_kib", "Output kept per task", "KiB" ],
    "poll_seconds" => [ "tasks.poll_seconds", "Agents poll for tasks every", "seconds" ]
  }.freeze
  EXPIRY_KEY = "tasks.expiry_hours".freeze

  # The limits in force. expiry_hours has every catalog type.
  Limits = Data.define(:max_hosts_per_batch, :output_limit_kib, :poll_seconds, :expiry_hours) do
    def output_limit_bytes = output_limit_kib.kilobytes

    def expiry(type) = expiry_hours.fetch(type).hours

    def to_h = { "max_hosts_per_batch" => max_hosts_per_batch, "output_limit_kib" => output_limit_kib, "poll_seconds" => poll_seconds, "expiry_hours" => expiry_hours }
  end

  module_function

  # One SELECT.
  def limits
    stored = Setting.where(key: LIMITS.values.map(&:first) + [ EXPIRY_KEY ]).pluck(:key, :value).to_h
    values = LIMITS.transform_values { |(key)| stored.fetch(key) { Setting::DEFINITIONS.fetch(key)[:default] } }
    expiry = stored.fetch(EXPIRY_KEY, {})
    Limits.new(**values.transform_keys(&:to_sym), expiry_hours: TaskCatalog.current.types.index_with { |type| expiry.fetch(type) { default_expiry_hours(type) } })
  end

  def max_hosts_per_batch = limits.max_hosts_per_batch

  def output_limit_bytes = limits.output_limit_bytes

  def poll_seconds = limits.poll_seconds

  def expiry(type) = limits.expiry(type)

  def default_expiry_hours(type) = (TaskCatalog.current.entry(type).expiry / 1.hour).ceil.clamp(expiry_range)

  def expiry_range = Setting::DEFINITIONS.fetch(EXPIRY_KEY)[:range]

  def range(field) = Setting::DEFINITIONS.fetch(LIMITS.fetch(field).first)[:range]

  # values: { "max_hosts_per_batch" => "10", "expiry_hours" => { "restart_service" => "12" }, ... } from the form; a
  # field left out keeps its value. Raises Invalid with every problem and changes nothing, or saves the changed values
  # and writes one audit entry. Returns the changes, { "tasks.max_hosts_per_batch" => [25, 10], ... } (empty when
  # nothing changed, and then nothing is audited).
  def update_limits!(values, actor:)
    values = values.to_h.stringify_keys
    parsed, errors = parse_limits(values)
    raise Invalid, errors if errors.any?

    transaction do
      current = limits
      changes = {}
      parsed.except("expiry_hours").each do |field, value|
        before = current.public_send(field)
        next if before == value

        write!(LIMITS.fetch(field).first, value)
        changes[LIMITS.fetch(field).first] = [ before, value ]
      end
      if (expiry = parsed["expiry_hours"])
        changed = expiry.reject { |type, hours| current.expiry_hours.fetch(type) == hours }
        if changed.any?
          stored = Setting.find_by(key: EXPIRY_KEY)&.value || {}
          write!(EXPIRY_KEY, stored.merge(changed).reject { |type, hours| hours == default_expiry_hours(type) })
          changed.each { |type, hours| changes["#{EXPIRY_KEY}.#{type}"] = [ current.expiry_hours.fetch(type), hours ] }
        end
      end
      Audit.record(actor:, action: Audit::Actions::TASK_SETTING_LIMITS_CHANGED, target: nil, changes:) if changes.any?
      changes
    end
  end

  # The allowlist, by service then scope (every host first).
  def allowlist = TaskAllowedService.includes(:added_by).order(:service, Arel.sql("tag NULLS FIRST")).to_a

  # Adds service for every host (tag blank) or for one tag. Raises Invalid when the name is not a service unit name,
  # is a template instance, is protected, or is already listed for that scope, or the list is full.
  def add_service!(service:, tag:, actor:)
    service = service.to_s.strip
    tag = tag.to_s.strip.presence
    errors = service_errors(service)
    errors["tag"] = "Choose every host or one tag." if tag && !tag.match?(Host::TAG_FORMAT)
    raise Invalid, errors if errors.any?

    transaction do
      before = allowlist
      raise Invalid, { "service" => "#{service} is already on the list for #{tag ? "hosts tagged #{tag}" : 'every host'}." } if before.any? { |entry| entry.service == service && entry.tag == tag }
      raise Invalid, { "service" => "The list holds at most #{MAX_SERVICES} services. Remove one first." } if before.size >= MAX_SERVICES

      entry = TaskAllowedService.create!(service:, tag:, added_by: actor, created_at: Time.current)
      audit_allowlist(Audit::Actions::TASK_SETTING_SERVICE_ADDED, entry, before, actor)
      entry
    end
  end

  # Removes the entry. Queued tasks that would restart the service are refused when their agent picks them up; a
  # restart already running finishes. Returns the removed entry, or nil if it was already gone.
  def remove_service!(id, actor:)
    transaction do
      before = allowlist
      entry = before.find { |candidate| candidate.id == id.to_i } or next nil

      entry.destroy!
      audit_allowlist(Audit::Actions::TASK_SETTING_SERVICE_REMOVED, entry, before, actor)
      entry
    end
  end

  # Queued and claimed restart tasks for this entry's service that would be refused at claim if it were removed now:
  # those on hosts no other entry covers. For the removal confirmation (settings-tasks.html).
  def tasks_refused_without(entry)
    others = allowlist.reject { |candidate| candidate.id == entry.id }
    Task.where(state: %w[queued claimed], task_type: "restart_service").where("parameters ->> 'service' = ?", entry.service)
        .includes(:host).select { |task| entry.applies_to?(task.host) && others.none? { |other| other.service == entry.service && other.applies_to?(task.host) } }
  end

  def service_errors(service)
    message = if service.empty? then "Type a service name, for example nginx.service."
    elsif service.include?("@") then "Instances such as getty@tty1.service are not accepted. Name the service itself."
    elsif service.length > TaskAllowedService::MAX_LENGTH || !service.match?(TaskAllowedService::SERVICE_FORMAT)
      "Not a service unit name. Use lower-case letters, digits, and - _ ., ending in .service, up to #{TaskAllowedService::MAX_LENGTH} characters."
    elsif TaskPolicy.protected_service?(service)
      "#{service} is protected. Protected services are never restarted remotely, so they cannot be added."
    end
    message ? { "service" => message } : {}
  end

  def parse_limits(values)
    parsed = {}
    errors = {}
    LIMITS.each_key do |field|
      next unless values.key?(field)

      value = whole_number(values[field])
      range = range(field)
      if field == "max_hosts_per_batch" && value && value > range.max
        errors[field] = "At most #{range.max}. The cap cannot be raised from the dashboard."
      elsif value.nil? || !range.cover?(value)
        errors[field] = "Enter a whole number from #{range.min} to #{range.max}."
      else
        parsed[field] = value
      end
    end
    if values.key?("expiry_hours")
      given = values["expiry_hours"].respond_to?(:to_h) ? values["expiry_hours"].to_h.stringify_keys : {}
      expiry = {}
      given.slice(*TaskCatalog.current.types).each do |type, raw|
        hours = whole_number(raw)
        if hours && expiry_range.cover?(hours)
          expiry[type] = hours
        else
          errors["expiry_hours.#{type}"] = "Enter a whole number of hours from #{expiry_range.min} to #{expiry_range.max}."
        end
      end
      parsed["expiry_hours"] = expiry if expiry.any?
    end
    [ parsed, errors ]
  end

  def whole_number(value)
    return value if value.is_a?(Integer)

    value.to_s.strip.match?(/\A\d{1,9}\z/) ? value.to_s.strip.to_i : nil
  end

  def write!(key, value)
    setting = Setting.lock.find_or_initialize_by(key:)
    setting.update!(value:)
  end

  def audit_allowlist(action, entry, before, actor)
    after = action == Audit::Actions::TASK_SETTING_SERVICE_ADDED ? (before + [ entry ]).sort_by { |e| [ e.service, e.tag.to_s ] } : before - [ entry ]
    Audit.record(actor:, action:, target: entry, changes: { "service" => entry.service, "hosts" => entry.scope, "allowlist" => [ before.map(&:label), after.map(&:label) ] })
  end

  def transaction(&)
    Setting.transaction(requires_new: true) do
      Setting.connection.execute("SELECT pg_advisory_xact_lock(hashtext(#{Setting.connection.quote(LOCK_KEY)}))")
      yield
    end
  end

  private_class_method :parse_limits, :whole_number, :write!, :audit_allowlist, :transaction, :service_errors
end
