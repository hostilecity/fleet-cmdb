# Staged agent rollouts and update outcomes (P1-UPDATES, FR-S.5, ADR 0018). The only code that changes a
# Rollout, RolloutHost, or AgentUpdate; every action and outcome is audited in the transaction that makes it.
#
# - start!, advance!, halt!, resume!, cancel! are the operator's actions.
# - directive_for builds the heartbeat's agent_update directive for one host (the server names a version and
#   where to fetch it, nothing else: ADR 0018).
# - record_result! stores an agent's reported outcome; a failure or rollback halts the rollout.
# - expire_unconfirmed! (run every minute by RolloutTimeoutJob) halts a rollout whose hosts never reported.
#
# Stages: stage 0 is the canaries (an explicit list of hosts, or a tag); stage n then brings the rollout to
# stage_percents[n - 1] percent of the hosts that run an older version. The default stages follow the fleet's
# size (default_stages, #199): 25 and 100 percent for a homelab, 1, 10, 50, and 100 from FLEET_ROLLOUT_LARGE_FLEET_HOSTS
# (1,000) active hosts.
# A stage's hosts are chosen before it opens, in batches of OPEN_BATCH and without the rollout lock, and its offers
# are spread over a window that grows with the stage (stage_spread); time spent halted does not count against the
# window (halted_seconds). A stage advances by itself when all its hosts have confirmed (RolloutAdvanceJob), or when
# an operator advances it. Only a running rollout sends directives; a halted one resumes only by operator action.
module Rollouts
  # field names the start form's control the problem is with (:release, :canary_tag, :stages), or nil.
  class Invalid < StandardError
    attr_reader :field

    def initialize(message = nil, field: nil)
      super(message)
      @field = field
    end
  end

  CANARY_TAG_LIMIT = 32 # rollouts.canary_tag
  DEFAULT_STAGES = [ 25, 100 ].freeze
  # From FLEET_ROLLOUT_LARGE_FLEET_HOSTS active hosts (config.large_fleet_hosts, default 1,000) the default stages are
  # LARGE_FLEET_STAGES (#199), so the first stage after the canaries is 1% of the fleet rather than a quarter of it.
  LARGE_FLEET_STAGES = [ 1, 10, 50, 100 ].freeze
  # Hosts chosen and inserted per statement when a stage opens (#199).
  OPEN_BATCH = 10_000
  # The advisory lock key that serialises a rollout's stage prepares: "roll" in ASCII, with the rollout id.
  PREPARE_LOCK_KEY = 0x726f6c6c
  # A fixed offset per host and rollout inside its stage's spread window (stage_spread), from a hash of the two, so it
  # is spread evenly and never moves: 0 to spread - 1 seconds. Binds: the rollout id, then the spread in seconds.
  # hashtextextended is the hash PostgreSQL's hash partitioning relies on, so it is stable across versions.
  OFFER_DELAY_SQL = "make_interval(secs => (hashtextextended(?::text || ':' || hosts.id, 0) & 9223372036854775807) % ?)".freeze
  # The same offset for a row already chosen (Rollouts.retime_stage!).
  RETIME_DELAY_SQL = "make_interval(secs => (hashtextextended(?::text || ':' || rollout_hosts.host_id, 0) & 9223372036854775807) % ?)".freeze
  # When an offer is due: its offer time moved on by the time the rollout has spent halted (#199), so a resume
  # releases the stage over what is left of its window, not all at once.
  OFFER_DUE_SQL = "rollout_hosts.offer_at + rollouts.halted_seconds * interval '1 second'".freeze
  DIRECTIVE_FILES = { manifest_url: "manifest", signature_url: "signature", binary_url: "binary" }.freeze
  # [rollout host id, its state, rollout id, release version] of a host's open offer (offer_scope), in this order.
  OFFER_COLUMNS = %w[rollout_hosts.id rollout_hosts.state rollouts.id agent_releases.version].freeze
  OUTCOME_STATES = { "succeeded" => "confirmed", "failed" => "failed", "rolled_back" => "rolled_back" }.freeze
  OUTCOME_ACTIONS = { "succeeded" => Audit::Actions::UPDATE_SUCCEEDED, "failed" => Audit::Actions::UPDATE_FAILED,
                      "rolled_back" => Audit::Actions::UPDATE_ROLLED_BACK }.freeze
  REASON_LIMIT = 500

  Result = Data.define(:report_id, :duplicate)

  module_function

  def config = Rails.configuration.x.rollouts

  # Starts a rollout of release. canary_host_ids and canary_tag name the first stage; stage_percents are the
  # later stages, each higher than the one before and ending at 100. Raises Invalid, changing nothing, when a
  # rollout is already open, the stages are wrong, or no canary is an active host running an older version.
  def start!(release:, actor:, canary_host_ids: [], canary_tag: nil, stage_percents: default_stages)
    percents = stage_percents!(stage_percents)
    ids, tag = canaries!(canary_host_ids, canary_tag)

    Rollout.transaction(requires_new: true) do
      raise Invalid, "A rollout is already open. Finish or cancel it first." if Rollout.open_now.lock.exists?

      now = Time.current
      rollout = Rollout.create!(agent_release: release, started_by: actor, canary_host_ids: ids, canary_tag: tag,
                                stage_percents: percents, started_at: now, stage_opened_at: now)
      added = prepare_stage!(rollout, 0).to_i # a new rollout: nothing else can be preparing it
      raise Invalid.new("None of the canaries is an active host running an older version than #{release.version}.", field: :canary_tag) if added.zero?

      Audit.record(actor:, action: Audit::Actions::ROLLOUT_STARTED, target: rollout,
                   changes: { "version" => [ nil, release.version ], "canary_host_ids" => ids, "canary_tag" => tag,
                              "stage_percents" => percents, "hosts_added" => added })
      FleetBroadcast.refresh
      rollout
    end
  rescue ActiveRecord::RecordNotUnique
    raise Invalid, "A rollout is already open. Finish or cancel it first."
  end

  # The default stages after the canaries for a fleet of active_hosts active hosts (#199).
  def default_stages(active_hosts = Host.active.count) = active_hosts >= config.large_fleet_hosts ? LARGE_FLEET_STAGES : DEFAULT_STAGES

  # The window a stage of hosts hosts spreads its offers over (#199): FLEET_ROLLOUT_SPREAD_SECONDS, or longer
  # when the stage is large, so that offers, and so downloads, come at most FLEET_ROLLOUT_DOWNLOADS_PER_SECOND a
  # second on average. 750,000 hosts at 10 a second take about 21 hours rather than 5 minutes.
  def stage_spread(hosts) = [ config.spread, (hosts.to_f / config.downloads_per_second).ceil ].max

  # The stages after the canaries, from a list ([25, 100]) or the dashboard's text ("25, 100"): increasing
  # percentages ending at 100. Raises Invalid otherwise.
  def stage_percents!(input)
    list = input.is_a?(String) ? input.split(/[\s,%]+/).reject(&:empty?) : Array(input)
    percents = list.map { |percent| Integer(percent.to_s, 10, exception: false) }
    unless percents.any? && percents.all? { |p| p&.between?(1, 100) } && percents.each_cons(2).all? { |a, b| a < b } && percents.last == 100
      raise Invalid.new("Stages must be increasing percentages ending at 100, such as 25, 100.", field: :stages)
    end

    percents
  end

  # The hosts a rollout of release started now would take as its canaries: active hosts, named or tagged, that
  # run an older version. What start! chooses, for the dashboard to confirm before starting. Raises Invalid
  # when no canary is named.
  def canary_hosts(release:, canary_host_ids: [], canary_tag: nil)
    ids, tag = canaries!(canary_host_ids, canary_tag)
    older_hosts(release.semver).merge(canary_scope(ids, tag))
  end

  # The operator opens the next stage now, without waiting for the current one to confirm.
  # expected_stage is the stage the operator saw when confirming (the dashboard sends it): if another operator, or
  # the stage's last confirmation, moved the rollout on since, nothing is advanced, so one confirmation can never
  # skip a stage nobody chose to skip.
  #
  # The next stage's hosts are chosen first, outside the rollout lock (prepare_stage!), so update results and the
  # timeout check never wait for a large stage to be chosen (review of #215). Only the advance itself, which re-checks
  # all of the above, takes the lock.
  def advance!(rollout, actor:, expected_stage: nil)
    rollout.reload
    check_advance!(rollout, expected_stage)
    expected = rollout.current_stage
    unless prepare_stage!(rollout, expected + 1)
      raise Invalid, "The next stage's hosts are being chosen right now. Try again in a minute."
    end
    in_state!(rollout, "running") do
      check_advance!(rollout, expected_stage || expected)
      advance_stage!(rollout, actor:, reason: "advanced by an operator")
    end
  end

  # Opens the stage after `from` once every host of `from` has confirmed (RolloutAdvanceJob): chooses its hosts without
  # the lock, then advances under it if the rollout is still running at `from` and the stage is still confirmed.
  # Does nothing otherwise, so a repeated or late job is harmless.
  def advance_confirmed!(rollout_id, from:)
    rollout = Rollout.find_by(id: rollout_id)
    return unless rollout && advanceable?(rollout, from)

    return unless prepare_stage!(rollout, from + 1) # another prepare is running; the backstop retries
    rollout.with_lock do
      next unless advanceable?(rollout, from)

      advance_stage!(rollout, actor: Audit::SYSTEM, reason: "all hosts in the stage confirmed")
      FleetBroadcast.refresh
    end
  end

  # Enqueues RolloutAdvanceJob for a running rollout whose current stage has confirmed and is not the last: a backstop
  # for an advance job that was lost, run every minute by RolloutTimeoutJob. It only enqueues: that job runs on the
  # realtime queue, which no long job may delay (S-7), and a stage's prepare can take minutes (review of #215). A
  # duplicate job is harmless: prepares are serialised and the advance re-checks the stage.
  def advance_confirmed_stages!
    Rollout.where(state: "running").find_each do |rollout|
      RolloutAdvanceJob.perform_later(rollout.id, rollout.current_stage) if advanceable?(rollout, rollout.current_stage)
    end
  end

  def halt!(rollout, actor:, reason: "halted by an operator")
    in_state!(rollout, "running") { halt_locked!(rollout, actor:, reason:) }
  end

  # Only an operator resumes a halted rollout.
  def resume!(rollout, actor:)
    in_state!(rollout, "halted") do
      now = Time.current
      # The time halted no longer counts against the open stage's window (#199): its pending offers stay spread.
      halted = rollout.halted_at ? (now - rollout.halted_at).floor : 0
      rollout.update!(state: "running", resumed_by: actor, resumed_at: now, halted_seconds: rollout.halted_seconds + halted)
      Audit.record(actor:, action: Audit::Actions::ROLLOUT_RESUMED, target: rollout,
                   changes: { "state" => [ "halted", "running" ], "reason" => rollout.halt_reason })
      advance_if_confirmed!(rollout, actor: Audit::SYSTEM)
    end
  end

  def cancel!(rollout, actor:)
    rollout.with_lock do
      raise Invalid, "The rollout is already #{rollout.state}." unless Rollout::OPEN_STATES.include?(rollout.state)

      before = rollout.state
      finish!(rollout, "cancelled")
      Audit.record(actor:, action: Audit::Actions::ROLLOUT_CANCELLED, target: rollout, changes: { "state" => [ before, "cancelled" ] })
      FleetBroadcast.refresh
    end
  end

  # The agent_update directive for a host, or nil. Only a host chosen for a stage that is open in the running
  # rollout, whose offer time has come and which runs an older version than the release, gets one; an agent
  # below the minimum agent version is no exception (FR-S.5). It is sent on every heartbeat until the host
  # reports a result, and the first time marks the host as updating and audits the request for that host. One
  # indexed SELECT when there is none.
  #
  # Runs inside the heartbeat's transaction. The offer is read without a lock on the rollout row (#199): before,
  # every heartbeat of a host in an open stage took the row FOR SHARE, which at scale is hundreds of thousands of
  # share lockers of one row, and a halt waiting behind all of them. Only a host's first offer (pending to updating)
  # takes the row, FOR SHARE SKIP LOCKED, and re-reads its state there (review of #215):
  # - a halt, cancel, or advance in progress holds the row FOR UPDATE, so the first offer is skipped (no directive
  #   this heartbeat; the next one tries again), and no heartbeat ever waits;
  # - one that committed is seen by the locking read, so once a halt or cancel commits, no host is offered the update;
  # - a halt or cancel waits only for the first offers in flight, about FLEET_ROLLOUT_DOWNLOADS_PER_SECOND a second.
  # A host already updating keeps getting its directive until it reports; it was offered before the halt. The stage
  # gate (rollout_hosts.stage <= rollouts.current_stage) is read in the same statement as the state, so an advance is
  # seen whole or not at all. Lock order elsewhere is host row, then rollout, then rollout host.
  #
  # The heartbeat reads offer_scope in one statement with its other directives (HeartbeatDirectives, #189) and builds
  # the directive with directive_from.
  def directive_for(host_id:, agent_version:, now: Time.current)
    directive_from(offer_scope(host_id:, now:).pick(*OFFER_COLUMNS), host_id:, agent_version:, now:)
  end

  # The host's open offer, at most one row, read without a lock on the rollout row (see directive_for, #199). Every
  # value is a bind parameter (no value inside SQL text), so the heartbeat's directives statement keeps the same text
  # and can be prepared (review of #209, HeartbeatDirectives); now is bound into OFFER_DUE_SQL's comparison.
  def offer_scope(host_id:, now:)
    due = Arel::Nodes::BindParam.new(ActiveRecord::Relation::QueryAttribute.new("offer_at", now, RolloutHost.type_for_attribute(:offer_at)))
    RolloutHost.joins(rollout: :agent_release)
               .where(host_id:, state: %w[pending updating], rollouts: { state: "running" })
               .where("rollout_hosts.stage <= rollouts.current_stage")
               .where(Arel::Nodes::LessThanOrEqual.new(Arel.sql(OFFER_DUE_SQL), due))
               .limit(1)
  end

  # The directive for an offer_scope row (OFFER_COLUMNS), or nil for none.
  def directive_from(row, host_id:, agent_version:, now:)
    return nil unless row

    id, state, rollout_id, version = row
    current = AgentApi::AgentVersion.parse(agent_version)
    return nil unless current && current < AgentApi::AgentVersion.parse(version)

    if state == "pending"
      # The first offer re-reads the rollout under a share lock that never waits (see directive_for).
      return nil unless Rollout.where(id: rollout_id, state: "running").lock("FOR SHARE SKIP LOCKED").exists?
    end
    if state == "pending" && RolloutHost.where(id:, state: "pending").update_all(state: "updating", offered_at: now, updated_at: now) == 1
      # Once per host and rollout, never on a repeat heartbeat: the request is on the host's audit trail even if the
      # rollout is cancelled before the host reports or times out.
      Audit.record(actor: Audit::SYSTEM, action: Audit::Actions::UPDATE_REQUESTED, target: Host.find(host_id),
                   changes: { "rollout_id" => rollout_id, "version" => version })
      FleetBroadcast.hosts_changed([ host_id ]) # the rollout shows the host as updating (P1-D09)
    end
    DIRECTIVE_FILES.transform_values { |file| Releases.download_url(version, file) }.merge(rollout_id:, version:)
  end

  # Stores the outcome an agent reported (POST /api/v1/update-results). Runs inside the request transaction,
  # under the host row lock (AgentHostLock). A report_id already stored is a duplicate and changes nothing.
  # Raises AgentApi::ValidationFailed for a rollout the host is not part of or a version that is not the
  # rollout's. A failed or rolled back update halts a running rollout; a late result is stored all the same.
  def record_result!(host_id:, credential_id:, payload:)
    host = AgentHostLock.lock!(host_id:, credential_id:)
    report_id = payload.fetch("report_id")
    return Result.new(report_id:, duplicate: true) if AgentUpdate.exists?(host_id:, report_id:)

    rollout = Rollout.lock.find_by(id: payload.fetch("rollout_id")) or reject!("/rollout_id", "No such rollout.")
    member = rollout.rollout_hosts.lock.find_by(host_id:) or reject!("/rollout_id", "This host is not part of that rollout.")
    reject!("/version", "This is not the version the rollout installs.") unless payload.fetch("version") == rollout.agent_release.version

    outcome = payload.fetch("outcome")
    now = Time.current
    reason = payload["reason"]&.gsub(/[[:cntrl:]]+/, " ")&.squish&.truncate(REASON_LIMIT)
    update = AgentUpdate.create!(host:, rollout:, report_id:, version: payload.fetch("version"), outcome:, reason:,
                                 reported_agent_version: payload.fetch("agent_version"),
                                 occurred_at: Time.iso8601(payload.fetch("occurred_at")), received_at: now)
    member.update!(state: OUTCOME_STATES.fetch(outcome), resolved_at: now)
    Audit.record(actor: host, action: OUTCOME_ACTIONS.fetch(outcome), target: update,
                 changes: { "rollout_id" => rollout.id, "version" => update.version, "reason" => reason })
    FleetBroadcast.hosts_changed([ host_id ])

    if outcome == "succeeded"
      advance_if_confirmed!(rollout, actor: Audit::SYSTEM)
    elsif rollout.state == "running"
      halt_locked!(rollout, actor: Audit::SYSTEM, reason: "#{host.name.truncate(100)} reported #{outcome.tr('_', ' ')}: #{reason}")
    end
    Result.new(report_id:, duplicate: false)
  end

  # Marks hosts that were sent the directive and have not reported within the confirmation timeout as
  # unconfirmed, and halts their running rollout. Returns the number of hosts marked. Idempotent.
  def expire_unconfirmed!(now: Time.current)
    cutoff = now - config.confirmation_timeout
    rollout_ids = RolloutHost.where(state: "updating").where(offered_at: ...cutoff).distinct.pluck(:rollout_id)
    rollout_ids.sum do |rollout_id|
      Rollout.transaction do
        rollout = Rollout.lock.find(rollout_id)
        next 0 unless rollout.state == "running"

        overdue = rollout.rollout_hosts.lock.where(state: "updating").where(offered_at: ...cutoff).to_a
        overdue.each do |member|
          member.update!(state: "unconfirmed", resolved_at: now)
          Audit.record(actor: Audit::SYSTEM, action: Audit::Actions::UPDATE_UNCONFIRMED, target: member,
                       changes: { "host_id" => member.host_id, "rollout_id" => rollout.id, "version" => rollout.agent_release.version,
                                  "reason" => "No result within #{config.confirmation_timeout.in_minutes.to_i} minutes." })
        end
        FleetBroadcast.hosts_changed(overdue.map(&:host_id))
        halt_locked!(rollout, actor: Audit::SYSTEM, reason: "#{overdue.size} host(s) did not confirm the update in time.") if overdue.any?
        overdue.size
      end
    end
  end

  # -- internals --

  # Locks the rollout row, re-reads it, and yields when it is in the given state. Open dashboards refresh once
  # the change commits (P1-D09).
  def in_state!(rollout, state, &)
    rollout.with_lock do
      raise Invalid, "The rollout is #{rollout.state}, not #{state}." unless rollout.state == state

      yield
      FleetBroadcast.refresh
    end
  end
  private_class_method :in_state!

  def halt_locked!(rollout, actor:, reason:)
    rollout.update!(state: "halted", halt_reason: reason.truncate(REASON_LIMIT), halted_at: Time.current,
                    halted_by: (actor if actor.is_a?(Operator)))
    Audit.record(actor:, action: Audit::Actions::ROLLOUT_HALTED, target: rollout,
                 changes: { "state" => [ "running", "halted" ], "reason" => rollout.halt_reason })
  end
  private_class_method :halt_locked!

  def finish!(rollout, state)
    rollout.update!(state:, open_slot: nil, finished_at: Time.current)
  end
  private_class_method :finish!

  def advance_if_confirmed!(rollout, actor:)
    return unless rollout.state == "running"
    return if rollout.rollout_hosts.where(stage: rollout.current_stage).where.not(state: "confirmed").exists?

    if rollout.final_stage?
      # After an operator advanced early, hosts of earlier stages may still be pending or updating. Completing now
      # would stop their directives and their timeout check, so a late failure or rollback would halt nothing.
      # Their results call back here, so the rollout completes once the last one confirms.
      return if rollout.rollout_hosts.where(state: %w[pending updating]).exists?

      finish!(rollout, "completed")
      Audit.record(actor:, action: Audit::Actions::ROLLOUT_COMPLETED, target: rollout, changes: { "state" => [ "running", "completed" ] })
    else
      # Choosing the next stage's hosts takes long for a large fleet, and this runs under the rollout lock (from an
      # update result, a resume, or an advance), so it is left to a job that chooses them first (advance_confirmed!).
      from = rollout.current_stage
      ActiveRecord.after_all_transactions_commit { RolloutAdvanceJob.perform_later(rollout.id, from) }
    end
  end
  private_class_method :advance_if_confirmed!

  # Raises Invalid unless the rollout can move on from expected_stage (the stage the operator saw, if given).
  def check_advance!(rollout, expected_stage)
    raise Invalid, "The rollout is #{rollout.state}, not running." unless rollout.state == "running"
    if expected_stage && rollout.current_stage != expected_stage
      raise Invalid, "The rollout already moved on to stage #{rollout.current_stage + 1} since you opened that page."
    end
    raise Invalid, "The rollout is already in its final stage." if rollout.final_stage?
  end
  private_class_method :check_advance!

  # Running at stage from, not the last, and every host of it confirmed.
  def advanceable?(rollout, from)
    rollout.state == "running" && rollout.current_stage == from && !rollout.final_stage? &&
      !rollout.rollout_hosts.where(stage: from).where.not(state: "confirmed").exists?
  end
  private_class_method :advanceable?

  # Under the rollout lock: opens the next stage, whose hosts prepare_stage! chose, in one short update.
  def advance_stage!(rollout, actor:, reason:)
    from = rollout.current_stage
    rollout.update!(current_stage: from + 1, stage_opened_at: Time.current)
    added = rollout.rollout_hosts.where(stage: from + 1).count
    Audit.record(actor:, action: Audit::Actions::ROLLOUT_ADVANCED, target: rollout,
                 changes: { "stage" => [ from, from + 1 ], "hosts_added" => added, "reason" => reason })
    advance_if_confirmed!(rollout, actor: Audit::SYSTEM) # a stage that added no host is confirmed already
  end
  private_class_method :advance_stage!

  # Chooses the hosts of stage `stage` and returns how many it has, or nil when another prepare of this rollout is
  # running (the caller gives up; the backstop tries again a minute later). Runs before the stage opens and without the
  # rollout lock (the stage gate, rollout_hosts.stage <= rollouts.current_stage, hides them until advance_stage!), in
  # its own short transactions, so update results and the timeout check never wait for it (review of #215). Hosts
  # that are not active, have not reported a version, or already run the release (or newer) are never chosen.
  #
  # Prepares of one rollout are serialised by a session-level advisory lock (with_prepare_lock): the advance job, the
  # backstop, a job delivered twice, and an operator's Advance would otherwise each add a full quota, and a 1% stage
  # would open at 2% or more (review of #215). Under it the quota is taken from the database in every batch. A stage
  # prepared before and not opened (an advance refused by a halt) is re-timed from now first, so its offers do not
  # all fall due the moment it opens.
  #
  # Uncached: each batch's INSERT runs inside a SELECT (a CTE), which does not clear Active Record's query cache, and the
  # quota must be counted afresh in every batch.
  def prepare_stage!(rollout, stage)
    ApplicationRecord.uncached { with_prepare_lock(rollout) { prepare_locked!(rollout, stage) } }
  end
  private_class_method :prepare_stage!

  def prepare_locked!(rollout, stage)
    begin
      older = older_hosts(rollout.agent_release.semver)
      older = older.merge(canary_scope(rollout.canary_host_ids, rollout.canary_tag)) if stage.zero?
      percent = stage.zero? ? 100 : rollout.stage_percents.fetch(stage - 1)
      members = rollout.rollout_hosts
      # Older hosts not in the rollout yet. A join, so a new rollout's missing statistics cannot make it quadratic.
      candidates = older.count - members.joins(:host).merge(older).count
      in_stage = members.where(stage:).count
      # The 100% stage takes every older host left (review of #215); a partial stage brings the rollout to its share
      # of the older hosts and those already in it: a total, so each batch can check it against the database.
      target = (((candidates + members.count) * percent / 100.0).ceil unless percent == 100)
      size = in_stage + (target ? [ target - members.count, 0 ].max : candidates)
      spread = stage_spread(size)
      # Offer times count from now; halted_seconds is subtracted so a past halt does not delay this stage (OFFER_DUE_SQL).
      base = Time.current - rollout.halted_seconds
      retime_stage!(rollout, stage, base:, spread:) if in_stage.positive?
      insert_stage_rows!(rollout, older, stage:, target:, spread:, base:)
      members.where(stage:).count
    end
  end
  private_class_method :prepare_locked!

  # Runs the block holding this rollout's prepare lock, or returns nil without running it when another session holds
  # it. Session-level (SessionLock), so it spans the prepare's own transactions; on the direct connection behind a
  # transaction-mode pooler (#198).
  def with_prepare_lock(rollout, &)
    SessionLock.hold(ApplicationRecord.sanitize_sql_array([ "?, ?::int", PREPARE_LOCK_KEY, rollout.id ]), &)
  end
  private_class_method :with_prepare_lock

  # Gives a prepared stage's pending hosts their offer times again, from base (review of #215).
  def retime_stage!(rollout, stage, base:, spread:)
    RolloutHost.where(rollout_id: rollout.id, stage:, state: "pending")
               .update_all([ "offer_at = ?::timestamp + #{RETIME_DELAY_SQL}, updated_at = ?", base, rollout.id, spread, Time.current ])
  end
  private_class_method :retime_stage!

  # Inserts older hosts that are not in the rollout yet, in host id order, until the rollout has target hosts (or, for
  # the 100% stage, target nil, until none is left). Each statement takes the next OPEN_BATCH older hosts after a
  # cursor and inserts them; the unique index on (rollout_id, host_id) skips those already chosen (ON CONFLICT DO
  # NOTHING), with no anti-join for the planner to get wrong: a new rollout's id has no statistics, and as a join that
  # was quadratic (32 s for the third batch of 10,000). The batch, the insert, and the next cursor come from one
  # statement, so one snapshot. What is still wanted is the target less the rollout's rows, counted in the batch's own
  # transaction, and a batch that adds more has its highest extra rows deleted by id there (review of #215). Each
  # host's offer time is base plus its offset (OFFER_DELAY_SQL).
  def insert_stage_rows!(rollout, older, stage:, target:, spread:, base:)
    after = 0
    loop do
      last = RolloutHost.transaction do
        wanted = target && (target - rollout.rollout_hosts.count)
        next nil if wanted && wanted <= 0

        batch = older.where("hosts.id > ?", after).order(:id).limit(OPEN_BATCH).select(:id, :agent_version)
        values = ApplicationRecord.sanitize_sql_array(
          [ "?, batch.id, ?, 'pending', ?::timestamp + #{OFFER_DELAY_SQL.sub('hosts.id', 'batch.id')}, batch.agent_version, ?::timestamp, ?::timestamp",
            rollout.id, stage, base, rollout.id, spread, Time.current, Time.current ]
        )
        last, inserted = RolloutHost.connection.select_rows(<<~SQL.squish).first
          WITH batch AS (#{batch.to_sql}),
          inserted AS (
            INSERT INTO rollout_hosts (rollout_id, host_id, stage, state, offer_at, from_version, created_at, updated_at)
            SELECT #{values} FROM batch ORDER BY batch.id
            ON CONFLICT (rollout_id, host_id) DO NOTHING RETURNING id, host_id
          )
          SELECT (SELECT max(id) FROM batch), (SELECT json_agg(json_build_array(host_id, id)) FROM inserted)
        SQL
        rows = inserted ? JSON.parse(inserted).sort : []
        RolloutHost.where(id: rows.drop(wanted).map(&:last)).delete_all if wanted && rows.size > wanted
        last
      end
      break unless last # the target is reached, or no older host is left

      after = last
    end
  end
  private_class_method :insert_stage_rows!

  # Active hosts that run an older version than target. Versions are compared in Ruby, but only the fleet's
  # distinct versions (a handful) are read; the hosts stay a query.
  def older_hosts(target)
    versions = Host.active.where.not(agent_version: nil).distinct.pluck(:agent_version).select do |version|
      semver = AgentApi::AgentVersion.parse(version)
      semver && semver < target
    end
    Host.active.where(agent_version: versions)
  end
  private_class_method :older_hosts

  # The named or tagged hosts, as a query: a large canary tag is never read into Ruby (review of #215).
  def canary_scope(ids, tag)
    named = Host.where(id: ids)
    tag ? named.or(Host.tagged(tag)) : named
  end
  private_class_method :canary_scope

  # The canary host ids and tag, cleaned; at least one of them is required.
  def canaries!(canary_host_ids, canary_tag)
    ids = Array(canary_host_ids).filter_map { |id| Integer(id.to_s, 10, exception: false) }.uniq
    tag = canary_tag.present? ? Host.normalize_tag(canary_tag) : nil
    raise Invalid.new("Name the canary hosts or a canary tag.", field: :canary_tag) if ids.empty? && tag.nil?
    raise Invalid.new("A canary tag is at most #{CANARY_TAG_LIMIT} characters.", field: :canary_tag) if tag && tag.length > CANARY_TAG_LIMIT

    [ ids, tag ]
  end
  private_class_method :canaries!

  def reject!(pointer, problem)
    raise AgentApi::ValidationFailed.new(details: [ { "pointer" => pointer, "problem" => problem } ])
  end
  private_class_method :reject!
end
