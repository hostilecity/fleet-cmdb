# Bulk task creation (FR-3.2, P3-S02): the only code that creates a TaskBatch or a Task.
#
#   TaskBatches.create!({ "type" => "restart_service", "parameters" => { "service" => "nginx.service" },
#                         "target" => { "tag" => "web" }, "confirm_host_count" => 4 }, operator:)
#
# The request is checked as a whole before anything is written, and any problem refuses it with every problem
# listed (Refused) and no records created:
# - Only the keys in REQUEST_KEYS and TARGET_KEYS are accepted. Anything else, such as a "command" or "script"
#   field, is refused, never ignored (AC-3.2).
# - The type must be in the task catalog, looked up by name; a catalog entry is never built from the request.
#   The parameters must validate against its closed schema (extra fields, wrong types, oversize values, values
#   outside an enum or pattern are refused) and pass the server's own policy (TaskPolicy, DEC-15).
# - The target is explicit host ids or one tag, never both. It is resolved once, under a share lock on the host
#   rows, and recorded on the batch: later changes to a host's tags or state do not change who the batch targets.
#   A selection of more hosts than the batch limit is refused, whether or not they would all be targeted: the limit
#   is the setting in Settings: Tasks (TaskSettings, P3-S06), never above MAX_HOSTS (DEC-14).
# - Hosts that are not active, or whose agent does not support and enable the type (P3-A01), or, for a restart,
#   that no server allowlist entry covers (an entry for another tag, Q31) or whose agent does not list the service
#   in its own allowlist (P3-D01 Q7), are excluded and listed with the reason (EXCLUSION_REASONS). If no host is
#   left, nothing is created.
# - Above CONFIRM_ABOVE targeted hosts, confirm_host_count must equal the number of tasks to create (DEC-14),
#   enforced here so a caller that skips the dashboard's form is held to it too.
#
# Then, in one transaction, it creates the batch and one queued task per targeted host, each with its own expiry
# (the type's setting, by default the catalog's 24 hours to start, DEC-14) and timeout from the catalog, audited as task.batch_created and task.created with
# the operator as actor. Each task is independent: one failing, being cancelled, or expiring never changes another.
#
# The dashboard's create flow (P3-S08) adds two keywords. expected_host_ids: the hosts its confirmation page showed;
# if the hosts the request resolves to now differ, it is refused (Q13) and the operator confirms again.
# confirmation_token: the confirmation's one-time id, stored on the batch, so a second submit of the same page
# cannot create a second batch (threat model H10). TaskBatches.preview does the same checks as create! up to the
# typed count and writes nothing, for drawing the targets and confirmation pages.
module TaskBatches
  # DEC-14: a hard cap of 25 hosts per batch (the setting may lower it), and the host count typed to confirm above 3.
  MAX_HOSTS = 25
  CONFIRM_ABOVE = 3

  REQUEST_KEYS = %w[type parameters target confirm_host_count].freeze
  TARGET_KEYS = %w[host_ids tag].freeze
  EXCLUSION_REASONS = %w[not_active machine_id_mismatch no_capability_report not_supported not_enabled not_allowed_on_server
                         not_allowed_locally].freeze

  # The request was refused and nothing was created. errors: [{ "pointer", "problem" }], JSON Pointers into the
  # request; excluded: the Exclusions found before it was refused (empty if it was refused before targeting).
  class Refused < StandardError
    attr_reader :errors, :excluded

    def initialize(errors, excluded: [])
      @errors = errors
      @excluded = excluded
      super("task request refused: #{errors.map { |e| "#{e['pointer'].presence || '/'} #{e['problem']}" }.join('; ')}")
    end
  end

  Exclusion = Data.define(:host_id, :reason) do
    def as_json(*) = { "host_id" => host_id, "reason" => reason }
  end

  Result = Data.define(:batch, :tasks, :excluded)

  # What a request would do now: the catalog entry, the validated parameters, the target as given, every host the
  # target selects (id order), the hosts it would run on, and the Exclusions.
  Preview = Data.define(:entry, :parameters, :target, :hosts, :targeted, :excluded) do
    def targeted_ids = targeted.map(&:id)
  end

  module_function

  def create!(request, operator:, now: Time.current, expected_host_ids: nil, confirmation_token: nil)
    TaskBatch.transaction(requires_new: true) do
      preview = preview(request, lock: true)
      entry, parameters, target, hosts, targeted, excluded = preview.deconstruct
      check_expected(preview, expected_host_ids) if expected_host_ids
      check_targets(targeted, excluded, request["confirm_host_count"])

      limits = TaskSettings.limits
      batch = TaskBatch.create!(operator:, task_type: entry.type, parameters:, selection_method: target.key?("tag") ? "tag" : "explicit",
                                selection_tag: target["tag"], selected_host_ids: hosts.map(&:id), excluded_hosts: excluded.map(&:as_json),
                                confirmed_host_count: request["confirm_host_count"], catalog_version: TaskCatalog.current.version,
                                catalog_digest: TaskCatalog.current.digest, confirmation_token:, created_at: now)
      Audit.record(actor: operator, action: Audit::Actions::TASK_BATCH_CREATED, target: batch, changes: {
        "task_type" => entry.type, "parameters" => parameters, "selection_method" => batch.selection_method, "tag" => batch.selection_tag,
        "host_ids" => targeted.map(&:id), "excluded" => excluded.map(&:as_json)
      }.compact)
      tasks = targeted.map do |host|
        task = batch.tasks.create!(host:, task_type: entry.type, parameters:, expires_at: now + limits.expiry(entry.type),
                                   timeout_seconds: entry.timeout.to_i, created_at: now, updated_at: now)
        Audit.record(actor: operator, action: Audit::Actions::TASK_CREATED, target: task,
                     changes: { "task_type" => entry.type, "host_id" => host.id, "batch_id" => batch.id, "expires_at" => task.expires_at.utc.iso8601 })
        task
      end
      Result.new(batch:, tasks:, excluded:)
    end
  end

  # The checks of create! up to the typed count, with nothing written: a Preview, or Refused with every problem. A
  # target that leaves no host is not refused here; its Preview has no targeted hosts. lock: true share-locks the
  # selected host rows (create! uses it, inside its transaction).
  def preview(request, lock: false)
    max_hosts = TaskSettings.max_hosts_per_batch
    entry, parameters, target = check_request(request, max_hosts)
    hosts = resolve(target, max_hosts, lock:)
    allowlist = TaskPolicy.restart_allowlist if entry.type == "restart_service"
    reasons = hosts.to_h { |host| [ host, exclusion_reason(host, entry, parameters, allowlist) ] }
    targeted, excluded = hosts.partition { |host| reasons[host].nil? }
    Preview.new(entry:, parameters:, target:, hosts:, targeted:, excluded: excluded.map { |host| Exclusion.new(host_id: host.id, reason: reasons[host]) })
  end

  # Why the host is left out, or nil; allowlist is TaskPolicy.restart_allowlist for a restart. A restart the server's
  # allowlist does not allow on this host (an entry for another tag) is not_allowed_on_server, ahead of the agent's
  # own allowlist.
  def exclusion_reason(host, entry, parameters, allowlist)
    reason = host.task_exclusion_reason(entry, parameters)
    return reason unless allowlist && (reason.nil? || reason == "not_allowed_locally")

    TaskPolicy.restart_allowed?(parameters["service"], host:, entries: allowlist) ? reason : "not_allowed_on_server"
  end

  # [entry, parameters, target] for a well-formed request; raises Refused with every problem otherwise.
  def check_request(request, max_hosts)
    raise Refused, [ problem("", "must be an object") ] unless request.is_a?(Hash) && request.keys.all?(String)

    errors = (request.keys - REQUEST_KEYS).sort.map { |key| problem("/#{escape(key)}", "is not accepted") }
    errors << problem("/type", "is required") unless request.key?("type")
    errors << problem("/parameters", "is required; send {} for a type without parameters") unless request.key?("parameters")
    errors.concat(target_errors(request["target"], max_hosts))
    count = request["confirm_host_count"]
    errors << problem("/confirm_host_count", "must be a whole number") unless count.nil? || count.is_a?(Integer)
    # The policy checks the type first, then the parameters; without parameters only an unknown type is reported.
    refusal = TaskPolicy.refusal(request["type"], request["parameters"]) if request.key?("type")
    errors.concat(refusal.errors) if refusal && (refusal.reason == "unknown_type" || request.key?("parameters"))
    raise Refused, errors if errors.any?

    entry = TaskCatalog.current.entry(request["type"])
    [ entry, request["parameters"].slice(*entry.parameter_names).deep_dup, request["target"] ]
  end

  def target_errors(target, max_hosts)
    return [ problem("/target", "is required: host_ids or tag") ] if target.nil?
    return [ problem("/target", "must be an object with host_ids or tag") ] unless target.is_a?(Hash) && target.keys.all?(String)

    errors = (target.keys - TARGET_KEYS).sort.map { |key| problem("/target/#{escape(key)}", "is not accepted") }
    given = target.keys & TARGET_KEYS
    return errors << problem("/target", "must have exactly one of host_ids or tag") unless given.size == 1

    if given == [ "tag" ]
      tag = target["tag"]
      errors << problem("/target/tag", "must be a tag such as web (1 to 32 lower-case letters, digits, - or _)") unless tag.is_a?(String) && tag.match?(Host::TAG_FORMAT)
    else
      ids = target["host_ids"]
      if !ids.is_a?(Array) || ids.empty? || !ids.all? { |id| id.is_a?(Integer) && id.positive? }
        errors << problem("/target/host_ids", "must be a list of host ids")
      elsif ids.size > max_hosts
        errors << problem("/target/host_ids", "has #{ids.size} hosts; a batch may target at most #{max_hosts}")
      elsif ids.uniq.size != ids.size
        errors << problem("/target/host_ids", "lists a host more than once")
      end
    end
    errors
  end

  # The hosts the target selects, share-locked so their state cannot change until the batch is written, in id
  # order. Retired hosts are never selected by tag; an explicit id of one is listed as excluded (not_active).
  def resolve(target, max_hosts, lock:)
    if target.key?("tag")
      hosts = locked(Host.in_fleet.tagged(target["tag"]).order(:id).limit(max_hosts + 1), lock).to_a
      raise Refused, [ problem("/target/tag", "selects no host") ] if hosts.empty?
      raise Refused, [ problem("/target/tag", "selects more than #{max_hosts} hosts; a batch may target at most #{max_hosts}") ] if hosts.size > max_hosts
    else
      ids = target["host_ids"]
      hosts = locked(Host.where(id: ids).order(:id), lock).to_a
      missing = ids - hosts.map(&:id)
      raise Refused, missing.map { |id| problem("/target/host_ids/#{ids.index(id)}", "is not a host") } if missing.any?
    end
    hosts
  end

  def locked(scope, lock) = lock ? scope.lock("FOR SHARE") : scope

  # Q13: the hosts the batch would run on must be the ones the operator confirmed.
  def check_expected(preview, expected_host_ids)
    return if preview.targeted_ids.sort == Array(expected_host_ids).sort

    raise Refused.new([ problem("/target", "now resolves to different hosts than the ones you confirmed") ], excluded: preview.excluded)
  end

  def check_targets(targeted, excluded, confirmed)
    raise Refused.new([ problem("/target", "selects no host that can run this task type") ], excluded:) if targeted.empty?
    return if targeted.size <= CONFIRM_ABOVE || confirmed == targeted.size

    raise Refused.new([ problem("/confirm_host_count", "must be #{targeted.size}, the number of hosts this batch will run on") ], excluded:)
  end

  def problem(pointer, message) = { "pointer" => pointer, "problem" => message }

  def escape(key) = key.to_s.truncate(64).gsub("~", "~0").gsub("/", "~1")

  private_class_method :check_request, :target_errors, :resolve, :locked, :check_expected, :check_targets, :problem, :escape
end
