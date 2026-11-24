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
  has_one :host_config, dependent: :restrict_with_exception
  has_many :config_snapshots, dependent: :restrict_with_exception
  has_many :inventory_snapshots, dependent: :restrict_with_exception
  has_many :enrollment_tokens, dependent: :restrict_with_exception
  has_many :rollout_hosts, dependent: :restrict_with_exception
  has_many :agent_updates, dependent: :restrict_with_exception
  has_many :report_requests, dependent: :restrict_with_exception
  has_many :tasks, dependent: :restrict_with_exception
  # Per-heartbeat state, in a narrow table so heartbeats leave this row alone (#192); nil until the first heartbeat.
  has_one :liveness, class_name: "HostLiveness", dependent: :restrict_with_exception
  has_one :applicability, class_name: "HostApplicability", dependent: :restrict_with_exception # FR-2.6 (#258)

  validates :name, presence: true, length: { maximum: 100 }, format: { without: CONTROL_CHARACTERS }
  validates :hostname, presence: true, length: { maximum: 253 }, format: { with: HOSTNAME_FORMAT, allow_blank: true }
  validates :description, length: { maximum: 1_000 }, format: { without: CONTROL_CHARACTERS_EXCEPT_WHITESPACE }
  validates :notes, length: { maximum: 10_000 }, format: { without: CONTROL_CHARACTERS_EXCEPT_WHITESPACE }
  validates :enrollment_state, inclusion: { in: ENROLLMENT_STATES }
  validate :tags_are_valid

  # Read from host_liveness; nil for a host that has never sent a heartbeat. Lists preload :liveness.
  delegate :liveness_status, :last_seen_at, :agent_reported_at, to: :liveness, allow_nil: true

  before_create :require_pending_state
  before_update :require_transition_for_state_change
  before_destroy { raise HardDeleteNotAllowed, "hosts are retired, never deleted" }

  # Hosts in the fleet: everything except retired hosts. Fleet counts and lists start here (FR-1.1).
  scope :in_fleet, -> { where.not(enrollment_state: "retired") }
  scope :active, -> { where(enrollment_state: "active") }
  scope :with_enrollment_state, ->(state) { where(enrollment_state: state) }
  # Liveness applies to active hosts only.
  scope :with_liveness, ->(status) { active.joins(:liveness).where(host_liveness: { liveness_status: status }) }
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
      if changes.any?
        Audit.record(actor:, action: Audit::Actions::HOST_EDITED, target: self, changes:)
        FleetBroadcast.hosts_changed([ id ])
      end
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

  # Makes way for a new enrollment path, a new token or an approved onboarding re-enrollment (FR-1.1, DEC-17):
  # an active or revoked host moves to pending, its unused tokens expire, and any approved re-enrollment of it
  # is superseded, so only the newest path can enroll it (review of #61). Call under the host's row lock.
  # Returns whether the host changed state.
  def supersede_enrollment_paths!(actor:)
    transitioning = can_transition?(:begin_reenrollment)
    begin_reenrollment!(actor:) if transitioning
    enrollment_tokens.redeemable.update_all(expires_at: Time.current, updated_at: Time.current)
    OnboardingRequest.supersede_reenrollments!(self)
    transitioning
  end

  # pending -> active with a new credential: an enrollment token was redeemed or an onboarding request collected.
  # The old credential is revoked, and a new credential starts a new machine identity, so any clone warning from
  # the old one is cleared. details are added to the audit entry. Returns the AgentCredential::Issued.
  def enroll!(machine_id:, agent_version:, schema_version:, details: {})
    previous = agent_credentials.active.lock.to_a.each(&:revoke!)
    issued = AgentCredential.issue!(host: self, machine_id:)
    update!(agent_version:, agent_schema_version: schema_version, machine_id_mismatch_at: nil, reported_machine_id: nil)
    activate!(actor: self, details: { "key_id" => [ previous.map(&:key_id).join(",").presence, issued.record.key_id ] }.merge(details))
    issued
  end

  def can_transition?(event)
    TRANSITIONS.fetch(event)[:from].include?(enrollment_state)
  end

  def retired? = enrollment_state == "retired"

  # FR-S.1: the credential has been used from a machine other than the one it was enrolled on.
  def machine_id_mismatch? = machine_id_mismatch_at.present?

  # Why a task of this catalog entry's type cannot be created for this host, as one of
  # TaskBatches::EXCLUSION_REASONS, or nil when it can (FR-3.1, P3-S02). Only active hosts whose agent reports
  # a catalog that has the type, and implements and enables it, are targeted (P3-A01); a host whose credential
  # is in use on another machine (FR-S.1) is not.
  def task_exclusion_reason(entry, parameters = {})
    return "not_active" unless enrollment_state == "active"
    return "machine_id_mismatch" if machine_id_mismatch?
    return "no_capability_report" if task_capabilities_reported_at.nil? || task_catalog_version.nil?
    return "not_supported" unless task_catalog_version >= entry.since && task_types_supported.include?(entry.type)

    return "not_enabled" unless task_types_enabled.include?(entry.type)

    "not_allowed_locally" if entry.type == "restart_service" && !task_services_allowed.include?(parameters["service"])
  end

  # The agent runs in recovery mode (#180, ADR 0030): its last heartbeat said so. It kept failing on a version it had
  # confirmed, so it only heartbeats and installs a signed update; it sends no reports and runs no tasks.
  def recovering? = enrollment_state == "active" && agent_recovery_since.present?

  # Whether recovery mode is set up on the VM (#232, ADR 0030), as the last heartbeat's `units.recovery` said: :set_up,
  # :not_set_up, :unchecked (the agent could not check; re-review of #235), or :not_reported (an agent that does not say). nil for a host that is not active or has sent no
  # heartbeat, where the question does not arise. A host without it stops for good after a crash loop on a confirmed
  # version, until its units are refreshed.
  def recovery_mode_coverage
    return unless enrollment_state == "active" && first_seen_at

    agent_recovery_coverage&.to_sym || :not_reported
  end

  # How many times systemd restarted the agent within window before now (#251), from agent_recent_restarts, which
  # holds the server's time of each restart the heartbeats showed (Liveness.process_columns).
  def agent_restarts_within(window = Rollouts.restart_loop.window, now: Time.current) = Rollouts.restarts_since(agent_recent_restarts, now - window)

  # A restart loop (#251): more than the restart-loop limit of restarts within its window, as the fleet filter lists.
  def restart_loop?(now: Time.current) = agent_restarts_within(now:) > Rollouts.restart_loop.limit

  # Stores agent_restart_loop_at again for the restart-loop limit in force (review of #307, S1): the (limit + 1)th newest
  # restart of every host with restarts, in batches of `batch` by id, each its own statement. The heartbeat keeps it for
  # the limit in force when it wrote it, so this is needed once after FLEET_RESTART_LOOP_RESTARTS changes. Returns the
  # number of rows changed.
  def self.refresh_restart_loops!(batch: 10_000)
    position = Rollouts.restart_loop.limit + 1
    after = 0
    changed = 0
    loop do
      ids = where.not(agent_recent_restarts: nil).where("id > ?", after).order(:id).limit(batch).pluck(:id)
      break if ids.empty?

      changed += where(id: ids).where("agent_restart_loop_at IS DISTINCT FROM agent_recent_restarts[?]", position)
                               .update_all([ "agent_restart_loop_at = agent_recent_restarts[?]", position ])
      after = ids.last
    end
    changed
  end

  # How the agent process before the running one stopped (#251), in words, from what systemd told the unit's
  # ExecStopPost=. systemd's result for a kill at MemoryMax is oom-kill, or signal (status KILL) when it saw the process
  # exit before the cgroup's OOM event, so a SIGKILL says it may have been the memory limit. nil without a record.
  def agent_last_stop_words
    result = agent_last_stop_result
    return if result.nil?

    "#{LAST_STOP_WORDS.fetch(result) { signal_words(result) }} " \
      "(systemd: #{[ result, agent_last_stop_exit ].compact.join(', ')})"
  end

  LAST_STOP_WORDS = { "success" => "Stopped cleanly", "oom-kill" => "Killed at its memory limit", "exit-code" => "Exited with an error" }.freeze

  private

  def signal_words(result)
    return "Stopped" unless result == "signal"

    agent_last_stop_exit_status == 9 ? "Killed by SIGKILL, perhaps at its memory limit" : "Ended by a signal"
  end

  def agent_last_stop_exit
    status = agent_last_stop_exit_status
    case agent_last_stop_exit_code
    when "exited" then "exit status #{status}"
    when "killed", "dumped"
      verb = agent_last_stop_exit_code == "dumped" ? "dumped core on" : "killed by"
      "#{verb} #{status ? "signal #{status}#{' (SIGKILL)' if status == 9}" : 'a signal'}"
    end
  end

  public

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
  # A host whose credential is revoked, that starts re-enrolling, or that is retired gets none of the tasks queued
  # for it: they were meant for the machine it was (threat model V9, P3-S05). Its queued and claimed tasks are
  # cancelled, with the same actor; a running one ends by its result or its lease.
  TASK_CANCELLING_EVENTS = %i[revoke begin_reenrollment retire].freeze

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
      tasks.where(state: TaskCancellation::UNSTARTED).order(:id).lock.each { |task| task.cancel!(actor:) } if TASK_CANCELLING_EVENTS.include?(event)
      FleetBroadcast.hosts_changed([ id ])
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
