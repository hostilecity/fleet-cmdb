# Words and lamps for rollouts and agent updates (P1-D09, approved mockups agents.html, agents-halted.html, and
# host.html's "Agent updates"). Every status has its word; colour is never the only signal.
module RolloutsHelper
  PROBLEM_STATES = %w[failed rolled_back unconfirmed restart_loop].freeze
  # The order a stage's counts are listed in.
  STATE_WORDS = { "confirmed" => "confirmed", "updating" => "updating", "pending" => "waiting", "rolled_back" => "rolled back",
                  "failed" => "failed", "unconfirmed" => "not confirmed", "restart_loop" => "restarted too often" }.freeze

  # "1. Canary", "2. 25% of hosts", "3. Everyone else": stage 0 is the canaries; each later stage brings the
  # rollout up to its share of the hosts on an older version.
  def rollout_stage_name(rollout, stage)
    return "Canary" if stage.zero?

    percent = rollout.stage_percents.fetch(stage - 1)
    percent == 100 ? "Everyone else" : "#{percent}% of hosts"
  end

  def rollout_stage_number(stage) = stage.zero? ? "Canary" : (stage + 1).to_s

  def rollout_title(rollout)
    version = rollout.agent_release.version
    rollout.state == "running" ? "Rolling out #{version}" : "Rollout to #{version}, #{rollout.state}"
  end

  # Who stopped the rollout: an operator, or the system when a host failed, rolled back, or did not confirm.
  def rollout_halted_by(rollout)
    rollout.halted_by ? "Halted by #{rollout.halted_by.display_name}" : "Halted automatically"
  end

  # The CSS class of a stage card: the open stage, or the stage a halt stopped.
  def rollout_stage_class(rollout, stage)
    return unless stage == rollout.current_stage

    { "running" => "current", "halted" => "halted" }[rollout.state]
  end

  # The lamp for a stage card, from { state => hosts } for that stage.
  def rollout_stage_lamp(rollout, stage, counts)
    if stage > rollout.current_stage
      return tag.span(rollout.state == "running" ? "Waiting" : "Not started", class: "lamp")
    end

    total = counts.values.sum
    return tag.span("No host needed it", class: "lamp online") if total.zero?

    confirmed = counts.fetch("confirmed", 0)
    others = STATE_WORDS.except("confirmed").filter_map { |state, word| "#{counts[state]} #{word}" if counts[state].to_i.positive? }
    lamp = if counts.slice(*PROBLEM_STATES).values.sum.positive? then "offline"
    elsif confirmed == total then "online"
    else "stale"
    end
    tag.span([ "#{confirmed} of #{total} confirmed", *others ].join(", "), class: [ "lamp", lamp ])
  end

  # The small line under a stage card's lamp.
  def rollout_stage_progress(rollout, stage, counts, canary_names)
    if stage > rollout.current_stage
      "Hosts are chosen when it opens"
    elsif stage == rollout.current_stage && rollout.state == "running" && (until_at = Rollouts.observing_until(rollout))
      # #251: confirmed, and observed for restart loops before it moves on.
      next_step = rollout.final_stage? ? "then the rollout completes" : "then the next stage opens"
      "All confirmed; observing until #{until_at.utc.strftime('%H:%M UTC')}, #{next_step}"
    elsif stage.zero? && canary_names.any?
      total = counts.values.sum
      names = canary_names.first(3)
      total > names.size ? "#{names.join(', ')} and #{total - names.size} more" : names.join(", ")
    elsif stage == rollout.current_stage && rollout.state == "running"
      "Opened #{time_ago_in_words(rollout.stage_opened_at)} ago"
    elsif stage == rollout.current_stage && rollout.state == "halted"
      "Halted #{time_ago_in_words(rollout.halted_at)} ago"
    else
      pluralize(counts.values.sum, "host")
    end
  end

  # [lamp class, words, detail or nil] for one host in a rollout, used on the Agents page and on host detail.
  # reason is what the host reported with its latest result.
  def rollout_host_status(member, rollout, reason: nil)
    version = rollout.agent_release.version
    case member.state
    when "confirmed" then [ "online", "Confirmed on #{version}", looping_before_words(member) ]
    # Neutral: from_version is the version when the stage chose the host, and a manual upgrade or another update
    # may have changed it since. The From column shows it as that snapshot; the outcome does not claim it runs it.
    when "rolled_back" then [ "offline", "Rolled back", reason ]
    when "failed" then [ "offline", "Failed", reason ]
    when "unconfirmed" then [ "offline", "No result within #{Rollouts.config.confirmation_timeout.in_minutes.to_i} minutes", nil ]
    when "restart_loop" then [ "offline", restart_loop_words, nil ] # #251
    when "updating" then [ "stale", "Offered #{version}, waiting for its result", looping_before_words(member) ]
    else pending_status(member, rollout, version)
    end
  end

  def rollout_host_lamp(member, rollout, reason: nil)
    lamp, words, detail = rollout_host_status(member, rollout, reason:)
    safe_join([ tag.span(words, class: [ "lamp", lamp ]), (tag.span(detail, class: "why") if detail.present?) ].compact)
  end

  # One line of a host's update history: "0.1.0 → 0.2.0, rolled back".
  def agent_update_summary(member, rollout)
    lamp, = rollout_host_status(member, rollout)
    outcome = { "confirmed" => nil, "rolled_back" => "rolled back", "failed" => "failed", "unconfirmed" => "not confirmed",
                "restart_loop" => "restarted too often", "updating" => "updating", "pending" => (rollout.state == "running" ? "waiting" : "not offered") }[member.state]
    words = [ [ member.from_version, rollout.agent_release.version ].compact.join(" → "), outcome ].compact.join(", ")
    tag.span(words, class: [ "lamp", lamp ])
  end

  # The detail line under it: how long confirmation took, or what went wrong, and when.
  def agent_update_detail(member, rollout, update)
    when_text = utc(update&.received_at || member.resolved_at || member.offered_at || member.created_at)
    detail = case member.state
    when "confirmed"
      took = (update.received_at - member.offered_at).round if update && member.offered_at
      confirmed = took ? "Confirmed in #{took < 60 ? pluralize(took, 'second') : human_duration(took)}" : "Confirmed"
      # A succeeded result may carry a note, such as units the agent could not refresh after the update (#232).
      [ confirmed, update&.reason.presence, looping_before_words(member) ].compact.join("; ")
    when "rolled_back", "failed"
      # The version the agent reported with the result is what it ran then, unlike from_version (a snapshot).
      [ update&.reason.presence, ("reported by #{update.reported_agent_version}" if update&.reported_agent_version.present?) ]
        .compact.join("; ").upcase_first.presence || "No reason given"
    else
      rollout_host_status(member, rollout)[1]
    end
    "#{detail}. #{when_text}"
  end

  # For a host that was already in a restart loop when it was offered the update (#251, owner decision 2026-11-23):
  # its restarts do not count towards the halt, and this says why. nil otherwise.
  def looping_before_words(member)
    return unless Rollouts.looping_before_offer?(member)

    "looping before this update (#{pluralize(member.restarts_before_offer, 'restart')} in the #{pluralize(Rollouts.restart_loop.window.in_hours.to_i, 'hour')} before it), so not counted"
  end

  # "Restarted more than 3 times within 24 hours of the update" (#251): the restart-loop settings in force.
  def restart_loop_words
    settings = Rollouts.restart_loop
    "Restarted more than #{pluralize(settings.limit, 'time')} within #{pluralize(settings.window.in_hours.to_i, 'hour')} of the update"
  end

  private

  def pending_status(member, rollout, version)
    return [ "awaiting", "Not offered while the rollout is halted", nil ] if rollout.state == "halted"
    return [ nil, "Not offered: the rollout was #{rollout.state}", nil ] unless rollout.state == "running"
    return [ "awaiting", "Offered #{version} from #{member.offer_at.utc.strftime('%H:%M UTC')}", nil ] if member.offer_at > Time.current

    [ "awaiting", "Waiting for its next heartbeat", nil ]
  end
end
