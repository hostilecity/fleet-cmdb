# The single entry point for the append-only audit log (FR-S.3, P1-S03).
#
#   Host.transaction do
#     host.update!(...)
#     Audit.record(actor: operator, action: Audit::Actions::HOST_EDITED, target: host, changes: { ... })
#   end
#
# Audit.record must run inside the transaction that makes the change, so a change can never be committed
# without its entry or an entry without its change.
module Audit
  class Error < StandardError; end
  class NotInTransaction < Error; end
  class UnknownAction < Error; end
  class SecretInChangeset < Error; end

  # The actor for changes made by the server itself (scheduled jobs, rake tasks).
  SYSTEM = :system

  module_function

  # actor:   Audit::SYSTEM, or a record that responds to audit_actor_type ("host", later "operator").
  # changes: { "field" => [before, after] } for edits; any JSON-serialisable hash otherwise.
  def record(actor:, action:, target: nil, changes: {}, request_id: Current.request_id)
    raise UnknownAction, "unknown audit action #{action.inspect}" unless Actions::ALL.include?(action)
    raise NotInTransaction, "Audit.record must run inside the transaction that makes the change" unless AuditEntry.connection.transaction_open?

    actor_type, actor_id = actor_columns(actor)
    AuditEntry.create!(
      actor_type:, actor_id:, action:,
      target_type: target&.class&.name, target_id: target&.id,
      changeset: Scrubber.call(changes.as_json, mode: secret_mode),
      request_id:
    )
  end

  def secret_mode
    Rails.env.production? ? :filter : :raise
  end

  def actor_columns(actor)
    return [ "system", nil ] if actor == SYSTEM
    raise ArgumentError, "audit actor must be Audit::SYSTEM or respond to audit_actor_type" unless actor.respond_to?(:audit_actor_type)
    raise ArgumentError, "audit actor must be saved" unless actor.id

    [ actor.audit_actor_type, actor.id ]
  end
end
