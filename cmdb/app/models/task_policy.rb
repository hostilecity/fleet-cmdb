# The server's own checks on what a task may do, beyond its catalog schema (FR-3.1, DEC-15). Used when a task is
# created (TaskBatches.create!) and again when it is claimed (Task#refusal_reason, P3-S03), so a change to the
# catalog or an allowlist after creation still stops the task.
#
# restart_service: the service must not be protected and must be on the server's restart allowlist. The
# allowlist is empty until the owner names services (DEC-15), and the setting that holds it comes with P3-S06,
# so until then every restart task is refused at creation.
module TaskPolicy
  # A refusal: a Task::REFUSED_REASONS reason, and problems as { "pointer", "problem" } for the request.
  Refusal = Data.define(:reason, :errors)

  # Always refused, even when listed (DEC-15): the agent's own units, SSH, systemd's own units, networking, and
  # D-Bus. Each name covers its template instances too (sshd@blue.service), and the agent's covers every unit
  # named after it (fleet-agent-rollback.service). Compared without regard to case.
  PROTECTED_SERVICES = [
    /\Afleet-agent([-@].*)?\.service\z/, /\Asshd?(@.*)?\.service\z/, /\Asystemd-.*\.service\z/,
    /\Anetworking(@.*)?\.service\z/, /\Anetworkmanager([-@].*)?\.service\z/, /\Aifup@.*\.service\z/,
    /\Adbus(-broker)?(@.*)?\.service\z/
  ].freeze

  module_function

  # The Refusal for this type and these parameters, or nil when the server allows them.
  def refusal(task_type, parameters)
    catalog = TaskCatalog.current
    return Refusal.new(reason: "unknown_type", errors: [ { "pointer" => "/type", "problem" => "is not a task type in the catalog" } ]) unless catalog.type?(task_type)

    errors = catalog.entry(task_type).parameter_errors(parameters)
    return Refusal.new(reason: "invalid_params", errors: errors.map { |e| e.merge("pointer" => "/parameters#{e['pointer']}") }) if errors.any?

    task_type == "restart_service" ? restart_refusal(parameters.fetch("service")) : nil
  end

  def protected_service?(service) = PROTECTED_SERVICES.any? { |pattern| pattern.match?(service.downcase) }

  # The services the server allows restart_service to name (DEC-15). Empty: the setting and its page are P3-S06.
  def restart_allowlist = [].freeze

  def restart_refusal(service)
    if protected_service?(service)
      Refusal.new(reason: "protected_service", errors: [ { "pointer" => "/parameters/service", "problem" => "is a protected service, which is never restarted remotely" } ])
    elsif !restart_allowlist.include?(service)
      Refusal.new(reason: "not_allowed_on_server", errors: [ { "pointer" => "/parameters/service", "problem" => "is not on the server's restart allowlist" } ])
    end
  end

  private_class_method :restart_refusal
end
