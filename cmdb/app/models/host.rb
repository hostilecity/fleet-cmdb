# A VM in the fleet (FR-1.1, P1-S02).
#
# Enrollment state changes only through the transition methods below, which follow the FR-1.1 table,
# raise InvalidTransition for anything else, and write an audit entry in the same transaction. Create and
# edit hosts with Host.register! and #edit! so those changes are audited too. Hosts are never deleted:
# retiring is the end of a host's life (retired is terminal). The hosts_guard database trigger enforces the
# same transition table and the no-delete rule for code paths that skip model callbacks.
class Host < ApplicationRecord
  class InvalidTransition < StandardError; end
  class HardDeleteNotAllowed < StandardError; end

  ENROLLMENT_STATES = %w[pending active revoked retired].freeze
  LIVENESS_STATUSES = %w[online stale offline].freeze

  # FR-1.1 transition table: event => allowed source states, target state, audit action.
  TRANSITIONS = {
    activate: { from: %w[pending], to: "active", action: Audit::Actions::HOST_ENROLLED },
    revoke: { from: %w[active], to: "revoked", action: Audit::Actions::HOST_CREDENTIAL_REVOKED },
    begin_reenrollment: { from: %w[active revoked], to: "pending", action: Audit::Actions::HOST_REENROLLMENT_STARTED },
    retire: { from: %w[pending active revoked], to: "retired", action: Audit::Actions::HOST_RETIRED }
  }.freeze

  EDITABLE_ATTRIBUTES = %w[name hostname description notes tags].freeze
  MAX_TAGS = 20
  TAG_FORMAT = /\A[a-z0-9][a-z0-9_-]{0,31}\z/
  # RFC 1123 labels, lowercase after normalisation.
  HOSTNAME_FORMAT = /\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\z/
  CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/
  CONTROL_CHARACTERS_EXCEPT_WHITESPACE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/

  has_many :agent_credentials, dependent: :restrict_with_exception
  has_many :status_events, class_name: "HostStatusEvent", dependent: :restrict_with_exception
  has_one :inventory, class_name: "HostInventory", dependent: :restrict_with_exception
  has_many :inventory_snapshots, dependent: :restrict_with_exception
  has_many :enrollment_tokens, dependent: :restrict_with_exception

  validates :name, presence: true, length: { maximum: 100 }, format: { without: CONTROL_CHARACTERS }
  validates :hostname, presence: true, length: { maximum: 253 }, format: { with: HOSTNAME_FORMAT, allow_blank: true }
  validates :description, length: { maximum: 1_000 }, format: { without: CONTROL_CHARACTERS_EXCEPT_WHITESPACE }
  validates :notes, length: { maximum: 10_000 }, format: { without: CONTROL_CHARACTERS_EXCEPT_WHITESPACE }
  validates :enrollment_state, inclusion: { in: ENROLLMENT_STATES }
  validates :liveness_status, inclusion: { in: LIVENESS_STATUSES }, allow_nil: true
  validate :tags_are_valid

  before_create :require_pending_state
  before_update :require_transition_for_state_change
  before_destroy { raise HardDeleteNotAllowed, "hosts are retired, never deleted" }

  # Hosts in the fleet: everything except retired hosts. Fleet counts and lists start here (FR-1.1).
  scope :in_fleet, -> { where.not(enrollment_state: "retired") }
  scope :active, -> { where(enrollment_state: "active") }
  scope :with_enrollment_state, ->(state) { where(enrollment_state: state) }
  # Liveness applies to active hosts only.
  scope :with_liveness, ->(status) { active.where(liveness_status: status) }
  scope :tagged, ->(tag) { where("hosts.tags @> ARRAY[?]::varchar[]", normalize_tag(tag)) }

  def self.normalize_tag(tag)
    tag.to_s.strip.downcase.gsub(/\s+/, "-")
  end

  # Creates a pending host and audits it. The enrollment token is issued separately (P1-API-AUTH).
  def self.register!(attributes, actor:)
    transaction(requires_new: true) do
      host = create!(attributes.to_h.stringify_keys.slice(*EDITABLE_ATTRIBUTES))
      Audit.record(actor:, action: Audit::Actions::HOST_CREATED, target: host,
                   changes: host.slice(*EDITABLE_ATTRIBUTES, "enrollment_state").transform_values { |v| [ nil, v ] })
      host
    end
  end

  # Updates operator-editable fields and audits the before and after values. No-op edits write nothing.
  def edit!(attributes, actor:)
    transaction(requires_new: true) do
      lock!
      assign_attributes(attributes.to_h.stringify_keys.slice(*EDITABLE_ATTRIBUTES))
      changes = changes_to_save.slice(*EDITABLE_ATTRIBUTES)
      save!
      Audit.record(actor:, action: Audit::Actions::HOST_EDITED, target: self, changes:) if changes.any?
    end
    self
  end

  # pending -> active: the agent redeemed its enrollment token. details are added to the audit entry.
  def activate!(actor:, details: {}) = transition!(:activate, actor:, details:)

  # active -> revoked: the operator revoked the credential. The active credential is revoked in the same
  # transaction, so it gets 401 on the next request (AC-1.5).
  def revoke!(actor:) = transition!(:revoke, actor:)

  # active or revoked -> pending: the operator issued a new enrollment token. For an active host the old
  # credential keeps working until the new token is redeemed (FR-1.1, DEC-04).
  def begin_reenrollment!(actor:) = transition!(:begin_reenrollment, actor:)

  # any -> retired (terminal). Retiring also revokes the active credential (FR-1.1).
  def retire!(actor:) = transition!(:retire, actor:)

  def can_transition?(event)
    TRANSITIONS.fetch(event)[:from].include?(enrollment_state)
  end

  def retired? = enrollment_state == "retired"

  # FR-S.1: the credential has been used from a machine other than the one it was enrolled on.
  def machine_id_mismatch? = machine_id_mismatch_at.present?

  # What the dashboard shows (FR-1.1, FR-1.4): liveness for active hosts, "awaiting first contact" for an
  # active host that has not sent a heartbeat yet, and the enrollment state for everything else.
  def display_status
    return enrollment_state unless enrollment_state == "active"

    liveness_status || "awaiting first contact"
  end

  def audit_actor_type = "host"

  def tags=(value)
    list = value.is_a?(String) ? value.split(",") : Array(value)
    super(list.map { |tag| self.class.normalize_tag(tag) }.reject(&:empty?).uniq)
  end

  def name=(value)
    super(value&.squish)
  end

  def hostname=(value)
    super(value&.strip&.downcase&.delete_suffix("."))
  end

  def delete
    raise HardDeleteNotAllowed, "hosts are retired, never deleted"
  end

  # update_column(s) skip callbacks, so guard the state here too. Bulk paths (update_all, delete_all) are
  # stopped by the hosts_guard database trigger.
  def update_columns(attributes)
    if attributes.to_h.stringify_keys.key?("enrollment_state") && !@transitioning
      raise InvalidTransition, "enrollment state changes only through the transition methods"
    end

    super
  end

  private

  # Transitions that end the host's current credential.
  REVOKING_EVENTS = %i[revoke retire].freeze

  def transition!(event, actor:, details: {})
    rule = TRANSITIONS.fetch(event)
    # requires_new: a savepoint, so a failed audit write rolls the change back even when the caller rescues
    # the error inside its own transaction.
    transaction(requires_new: true) do
      lock!
      unless rule[:from].include?(enrollment_state)
        raise InvalidTransition, "cannot #{event.to_s.tr('_', ' ')} a #{enrollment_state} host"
      end

      before = enrollment_state
      @transitioning = true
      update!(enrollment_state: rule[:to])
      revoked = REVOKING_EVENTS.include?(event) ? revoke_active_credentials : {}
      Audit.record(actor:, action: rule[:action], target: self,
                   changes: { "enrollment_state" => [ before, rule[:to] ] }.merge(revoked, details))
    ensure
      @transitioning = false
    end
    self
  end

  # Revokes the active credential, if any, and returns its key id (not secret) for the audit entry.
  def revoke_active_credentials
    credentials = agent_credentials.active.lock.to_a
    credentials.each(&:revoke!)
    credentials.any? ? { "revoked_key_id" => credentials.map(&:key_id).join(",") } : {}
  end

  def require_pending_state
    raise InvalidTransition, "new hosts start pending" unless enrollment_state == "pending"
  end

  def require_transition_for_state_change
    return unless enrollment_state_changed? && !@transitioning

    raise InvalidTransition, "enrollment state changes only through the transition methods"
  end

  def tags_are_valid
    errors.add(:tags, "can have at most #{MAX_TAGS} entries") if tags.size > MAX_TAGS
    invalid = tags.reject { |tag| tag.match?(TAG_FORMAT) }
    errors.add(:tags, "are invalid: #{invalid.join(', ')} (use 1-32 lowercase letters, digits, - or _)") if invalid.any?
  end
end
