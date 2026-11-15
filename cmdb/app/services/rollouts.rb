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
# size (default_stages, #199): 25 and 100 percent for a homelab, 1, 10, 50, and 100 from LARGE_FLEET active hosts.
# A stage's hosts are chosen when it opens, in batches of OPEN_BATCH, and its offers are spread over a window that
# grows with the stage (stage_spread). A stage advances by itself when all its hosts have confirmed, or when an
# operator advances it. Only a running rollout sends directives; a halted one resumes only by operator action.
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
  # From this many active hosts the default stages are LARGE_FLEET_STAGES (#199), so the first stage after the
  # canaries is 1% of the fleet rather than a quarter of it.
  LARGE_FLEET = 1_000
  LARGE_FLEET_STAGES = [ 1, 10, 50, 100 ].freeze
  # Hosts chosen and inserted per statement when a stage opens (#199).
  OPEN_BATCH = 10_000
  # A fixed offset per host and rollout inside its stage's spread window (stage_spread), from a hash of the two, so it
  # is spread evenly and never moves: 0 to spread - 1 seconds. Binds: the rollout id, then the spread in seconds.
  # hashtextextended is the hash PostgreSQL's hash partitioning relies on, so it is stable across versions.
  OFFER_DELAY_SQL = "make_interval(secs => (hashtextextended(?::text || ':' || hosts.id, 0) & 9223372036854775807) % ?)".freeze
  DIRECTIVE_FILES = { manifest_url: "manifest", signature_url: "signature", binary_url: "binary" }.freeze
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
      added = open_stage!(rollout, now)
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
  def default_stages(active_hosts = Host.active.count) = active_hosts >= LARGE_FLEET ? LARGE_FLEET_STAGES : DEFAULT_STAGES

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
    older_hosts(release.semver).where(id: canary_ids(ids, tag))
  end

  # The operator opens the next stage now, without waiting for the current one to confirm.
  # expected_stage is the stage the operator saw when confirming (the dashboard sends it): if another operator, or
  # the stage's last confirmation, moved the rollout on since, nothing is advanced, so one confirmation can never
  # skip a stage nobody chose to skip.
  def advance!(rollout, actor:, expected_stage: nil)
    in_state!(rollout, "running") do
      if expected_stage && rollout.current_stage != expected_stage
        raise Invalid, "The rollout already moved on to stage #{rollout.current_stage + 1} since you opened that page."
      end
      raise Invalid, "The rollout is already in its final stage." if rollout.final_stage?

      advance_stage!(rollout, actor:, reason: "advanced by an operator")
    end
  end

  def halt!(rollout, actor:, reason: "halted by an operator")
    in_state!(rollout, "running") { halt_locked!(rollout, actor:, reason:) }
  end

  # Only an operator resumes a halted rollout.
  def resume!(rollout, actor:)
    in_state!(rollout, "halted") do
      rollout.update!(state: "running", resumed_by: actor, resumed_at: Time.current)
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
  # Runs inside the heartbeat's transaction, and reads the rollout row without locking it (#199). Before, every
  # heartbeat of a host in an open stage took the row FOR SHARE: at scale, hundreds of thousands of share lockers of
  # one row (a MultiXact per combination), and a halt waiting for all of them while new heartbeats queued behind it.
  # Now a halt, cancel, or advance never waits for heartbeats. What that allows, and why it is safe:
  # - A heartbeat whose read began before a halt committed may still send the directive, at most milliseconds after
  #   the halt. It is at most one offer per host (pending to updating is one conditional UPDATE, audited once), and
  #   it is the offer the host would have had a moment earlier: the agent verifies the release itself (ADR 0018).
  # - Every heartbeat that starts after the halt commits reads it and offers nothing.
  # - The result of such an offer is still accepted (record_result! takes the rollout FOR UPDATE and stores late
  #   results), a failure still halts a running rollout, and an offered host that never reports is marked
  #   unconfirmed by expire_unconfirmed! once the rollout runs again.
  # The stage gate (rollout_hosts.stage <= rollouts.current_stage) is read in the same statement as the state, so an
  # advance is seen whole or not at all. Lock order elsewhere is host row, then rollout, then rollout host.
  def directive_for(host_id:, agent_version:, now: Time.current)
    row = RolloutHost.joins(rollout: :agent_release)
                     .where(host_id:, state: %w[pending updating], rollouts: { state: "running" })
                     .where("rollout_hosts.stage <= rollouts.current_stage AND rollout_hosts.offer_at <= ?", now)
                     .pick("rollout_hosts.id", "rollout_hosts.state", "rollouts.id", "agent_releases.version")
    return nil unless row

    id, state, rollout_id, version = row
    current = AgentApi::AgentVersion.parse(agent_version)
    return nil unless current && current < AgentApi::AgentVersion.parse(version)

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
      advance_stage!(rollout, actor:, reason: "all hosts in the stage confirmed")
    end
  end
  private_class_method :advance_if_confirmed!

  def advance_stage!(rollout, actor:, reason:)
    from = rollout.current_stage
    now = Time.current
    rollout.update!(current_stage: from + 1, stage_opened_at: now)
    added = open_stage!(rollout, now)
    Audit.record(actor:, action: Audit::Actions::ROLLOUT_ADVANCED, target: rollout,
                 changes: { "stage" => [ from, from + 1 ], "hosts_added" => added, "reason" => reason })
    advance_if_confirmed!(rollout, actor: Audit::SYSTEM) # a stage that added no host is confirmed already
  end
  private_class_method :advance_stage!

  # Chooses the hosts of the rollout's current stage and returns how many. Hosts that are not active, have
  # not reported a version, or already run the release (or newer) are never chosen. Hosts are chosen in host id
  # order, one host-id range of at most OPEN_BATCH hosts per INSERT ... SELECT (#199), so no statement and no Ruby
  # array holds the whole fleet. All batches are in the caller's transaction, so a stage opens whole or not at all.
  def open_stage!(rollout, now)
    stage = rollout.current_stage
    older = older_hosts(rollout.agent_release.semver)
    older = older.where(id: canary_ids(rollout.canary_host_ids, rollout.canary_tag)) if stage.zero?
    included = rollout.rollout_hosts.count
    # Older hosts not in the rollout yet. A join, so a new rollout's missing statistics cannot make it quadratic.
    candidates = older.count - rollout.rollout_hosts.joins(:host).merge(older).count
    wanted = if stage.zero?
      candidates
    else
      [ ((candidates + included) * rollout.stage_percents.fetch(stage - 1) / 100.0).ceil - included, 0 ].max
    end
    insert_stage_rows!(rollout, older, stage:, wanted:, spread: stage_spread(wanted), now:)
  end
  private_class_method :open_stage!

  # Inserts the first wanted older hosts that are not in the rollout yet, in host id order. Each statement takes the
  # next range of at most OPEN_BATCH older hosts, never more than are still wanted, and inserts them; the unique
  # index on (rollout_id, host_id) skips those already chosen (ON CONFLICT DO NOTHING), with no anti-join for the
  # planner to get wrong: a new rollout's id has no statistics, and as a join that was quadratic (32 s for the third
  # batch of 10,000). Earlier stages took the lowest ids, so the skipped hosts come first and cost one pass. Each
  # host's offer time is the opening time plus its offset (OFFER_DELAY_SQL), computed in the same statement.
  def insert_stage_rows!(rollout, older, stage:, wanted:, spread:, now:)
    added = 0
    after = 0
    while added < wanted
      size = [ OPEN_BATCH, wanted - added ].min
      upper = older.where("hosts.id > ?", after).order(:id).offset(size - 1).limit(1).pick(:id)
      range = older.where("hosts.id > ?", after)
      range = range.where("hosts.id <= ?", upper) if upper
      rows = range.select(Arel.sql(ApplicationRecord.sanitize_sql_array(
        [ "?, hosts.id, ?, 'pending', ?::timestamp + #{OFFER_DELAY_SQL}, hosts.agent_version, ?::timestamp, ?::timestamp",
          rollout.id, stage, now, rollout.id, spread, now, now ]
      )))
      added += RolloutHost.connection.exec_update(
        "INSERT INTO rollout_hosts (rollout_id, host_id, stage, state, offer_at, from_version, created_at, updated_at) " \
        "#{rows.to_sql} ON CONFLICT (rollout_id, host_id) DO NOTHING"
      )
      break unless upper # no older host is left

      after = upper
    end
    added
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

  def canary_ids(ids, tag)
    tagged = tag ? Host.active.tagged(tag).pluck(:id) : []
    ids | tagged
  end
  private_class_method :canary_ids

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
