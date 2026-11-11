# The server's own checks on what a task may do, beyond its catalog schema (FR-3.1, DEC-15). Used when a task is
# created (TaskBatches.create!) and again when it is claimed (Task#refusal_reason, P3-S03), so a change to the
# catalog or an allowlist after creation still stops the task.
#
# restart_service: the service must not be protected and must be on the server's restart allowlist
# (TaskAllowedService, P3-S06), which is empty until the owner names services (DEC-15), so until then every restart
# task is refused at creation. An entry is for every host or for one tag (Q31): for a host, only the entries that
# apply to it count; without a host (checking a request before its targets are known), any entry for the service.
module TaskPolicy
  # A refusal: a Task::REFUSED_REASONS reason, and problems as { "pointer", "problem" } for the request.
  Refusal = Data.define(:reason, :errors)

  # Always refused, even when listed (DEC-15): the agent's own units, SSH, systemd's own units, networking, and
  # D-Bus. Each name covers its template instances too (sshd@blue.service), and the agent's covers every unit
  # whose name starts with it (fleet-agent-rollback.service), as the agent's own check does (agent/src/tasks).
  # Compared without regard to case.
  PROTECTED_SERVICES = [
    /\Afleet-agent.*\.service\z/, /\Asshd?(@.*)?\.service\z/, /\Asystemd-.*\.service\z/,
    /\Anetworking(@.*)?\.service\z/, /\Anetworkmanager([-@].*)?\.service\z/, /\Aifup@.*\.service\z/,
    /\Adbus(-broker)?(@.*)?\.service\z/
  ].freeze

  # The protected services as Settings: Tasks lists them (mockup settings-tasks.html): names, and why.
  PROTECTED_SERVICE_NOTES = [
    [ "fleet-agent.service, fleet-agent-*.service", "The agent itself: restarting it would cut off the task that asked for it." ],
    [ "ssh.service, sshd.service", "Remote access to the VM." ],
    [ "systemd-*.service", "Parts of the service manager." ],
    [ "networking.service, NetworkManager.service, ifup@*.service", "The VM's network, and with it the agent's connection." ],
    [ "dbus.service, dbus-broker.service", "The message bus that systemd and other services depend on." ]
  ].freeze

  module_function

  # The Refusal for this type and these parameters, or nil when the server allows them. With host, a restart must be
  # allowed for that host (at claim time, by its tags then).
  def refusal(task_type, parameters, host: nil)
    catalog = TaskCatalog.current
    return Refusal.new(reason: "unknown_type", errors: [ { "pointer" => "/type", "problem" => "is not a task type in the catalog" } ]) unless catalog.type?(task_type)

    errors = catalog.entry(task_type).parameter_errors(parameters)
    return Refusal.new(reason: "invalid_params", errors: errors.map { |e| e.merge("pointer" => "/parameters#{e['pointer']}") }) if errors.any?

    task_type == "restart_service" ? restart_refusal(parameters.fetch("service"), host) : nil
  end

  def protected_service?(service) = PROTECTED_SERVICES.any? { |pattern| pattern.match?(service.downcase) }

  # The server's restart allowlist entries (DEC-15, Settings: Tasks).
  def restart_allowlist = TaskAllowedService.all.to_a

  # Whether the server allows restarting this service: on host, or (host nil) on any host.
  def restart_allowed?(service, host: nil, entries: restart_allowlist)
    entries.any? { |entry| entry.service == service && (host.nil? || entry.applies_to?(host)) }
  end

  def restart_refusal(service, host)
    if protected_service?(service)
      Refusal.new(reason: "protected_service", errors: [ { "pointer" => "/parameters/service", "problem" => "is a protected service, which is never restarted remotely" } ])
    elsif !restart_allowed?(service, host:)
      problem = host ? "is not on the server's restart allowlist for this host" : "is not on the server's restart allowlist"
      Refusal.new(reason: "not_allowed_on_server", errors: [ { "pointer" => "/parameters/service", "problem" => problem } ])
    end
  end

  private_class_method :restart_refusal
end
