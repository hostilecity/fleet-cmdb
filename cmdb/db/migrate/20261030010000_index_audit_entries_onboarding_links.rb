# The audit log page (P1-AUDIT-PAGE) links an onboarding request to its host through the log itself, because
# requests are pruned a day after they expire: a host's "Enrolled" entry names the request it collected, and
# a re-enrollment approval names the host. These partial expression indexes let the page follow those links
# in both directions without scanning every enrollment or approval. They cover only those two actions, so
# they stay small. Built concurrently, so the append-only log keeps taking writes while they build.
class IndexAuditEntriesOnboardingLinks < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    add_index :audit_entries, "(changeset #>> '{onboarding_request_id,1}')",
              name: "index_audit_entries_on_enrolled_onboarding_request", where: "action = 'host.enrolled'", algorithm: :concurrently
    add_index :audit_entries, "(changeset #>> '{host_id,1}')",
              name: "index_audit_entries_on_approved_host", where: "action = 'onboarding.approved'", algorithm: :concurrently
  end
end
