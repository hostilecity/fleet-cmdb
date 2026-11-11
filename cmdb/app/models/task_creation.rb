# What the create-task flow (P3-S08, mockups create-*.html) needs to know about the catalog and the fleet, beyond
# what TaskBatches checks: which types any host will run, which parameters the dashboard can offer, and the
# restart allowlist as a list to choose from. Nothing here decides whether a task may be created; TaskBatches does
# that on every request, so the pages are a convenience, not a control.
module TaskCreation
  # One catalog entry as the type step shows it. hosts_running counts active hosts whose agent reports the type as
  # supported and enabled; unavailable is nil, or why the type cannot be chosen now (UNAVAILABLE).
  Choice = Data.define(:entry, :hosts_running, :active_hosts, :unavailable) do
    def available? = unavailable.nil?
  end

  # Why a type is drawn unavailable on the type step (mockup create-type.html#one-off).
  #   no_form          the dashboard has no control for one of its parameters (never a text box: see form_supported?)
  #   empty_allowlist  restart_service with nothing on the server's restart allowlist (ADR 0015)
  #   no_host          no active host's agent supports and enables it
  UNAVAILABLE = %w[no_form empty_allowlist no_host].freeze

  # A service on the restart allowlist, with the tags it is allowed for; tags is nil when it is allowed everywhere.
  Service = Data.define(:service, :tags)

  module_function

  def choices
    active = Host.active.count
    allowlist_empty = !TaskAllowedService.exists?
    TaskCatalog.current.entries.map do |entry|
      running = capable_hosts(entry).count
      unavailable = if !form_supported?(entry) then "no_form"
      elsif entry.type == "restart_service" && allowlist_empty then "empty_allowlist"
      elsif running.zero? then "no_host"
      end
      Choice.new(entry:, hosts_running: running, active_hosts: active, unavailable:)
    end
  end

  def choice(entry) = choices.find { |choice| choice.entry == entry }

  # Active hosts whose agent reports the type as supported and enabled (P3-A01), not counting a restart's allowlists.
  def capable_hosts(entry)
    Host.active.where(machine_id_mismatch_at: nil).where(task_catalog_version: entry.since..)
        .where("? = ANY (task_types_supported) AND ? = ANY (task_types_enabled)", entry.type, entry.type)
  end

  # Whether any active host's agent runs tasks at all (mockup create-blocked.html#no-support).
  def any_agent_runs_tasks? = Host.active.where.not(task_capabilities_reported_at: nil).where("cardinality(task_types_supported) > 0").exists?

  # The dashboard offers a parameter only as a choice from a fixed list, never as a text box (P3-S08: no free-text
  # field is sent anywhere): the restart service comes from the allowlist (Q5). A later catalog type with another
  # kind of parameter is shown unavailable until the dashboard has a control for it.
  def form_supported?(entry) = entry.parameters.all? { |parameter| entry.type == "restart_service" && parameter.name == "service" }

  # The restart allowlist as choices, in name order: one per service, with its tags (or nil for every host).
  def services
    TaskAllowedService.order(:service, :tag).group_by(&:service).map do |service, entries|
      Service.new(service:, tags: entries.any? { |entry| entry.tag.nil? } ? nil : entries.map(&:tag))
    end
  end

  # Tags in the fleet, with how many hosts have each, in name order: [["web", 10], ...].
  def tags = Host.in_fleet.pluck(Arel.sql("unnest(tags)")).tally.sort

  # Hosts in the fleet to pick from, by name, optionally those whose name or hostname contains query; at most limit.
  def pickable_hosts(query, limit:)
    scope = Host.in_fleet.order(:name, :id)
    if query.present?
      pattern = "%#{Host.sanitize_sql_like(query.to_s.first(100))}%"
      scope = scope.where("hosts.name ILIKE :pattern OR hosts.hostname ILIKE :pattern", pattern:)
    end
    scope.limit(limit).to_a
  end
end
