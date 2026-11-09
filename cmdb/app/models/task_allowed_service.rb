# One entry on the server's restart allowlist (DEC-15, P3-S06, owner decision Q31): a full .service unit name, for
# every host (tag nil) or for the hosts with one tag. Added and removed only through TaskSettings, which checks the
# name, refuses protected services, and audits the change with the list before and after.
class TaskAllowedService < ApplicationRecord
  # A unit name as systemctl shows it: lower-case letters, digits, and - _ ., ending in .service, at most 64
  # characters. No template instances (@), so an entry names exactly one unit. The database checks it too.
  SERVICE_FORMAT = /\A[a-z0-9][a-z0-9_.-]{0,55}\.service\z/
  MAX_LENGTH = 64

  belongs_to :added_by, class_name: "Operator"

  validates :service, format: { with: SERVICE_FORMAT }
  validates :tag, format: { with: Host::TAG_FORMAT }, allow_nil: true

  # Whether this entry lets the service be restarted on this host.
  def applies_to?(host) = tag.nil? || host.tags.include?(tag)

  # "every host" or "tag web", as the audit log records the entry's scope.
  def scope = tag ? "tag #{tag}" : "every host"

  # "nginx.service (tag web)", as the audit log records the list before and after a change.
  def label = "#{service} (#{scope})"
end
