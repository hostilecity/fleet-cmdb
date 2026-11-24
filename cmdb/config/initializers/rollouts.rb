# Agent rollouts (P1-UPDATES, ADR 0018). Environment files may set any of these first; tests do.
Rails.application.configure do
  rollouts = config.x.rollouts

  # Opening a stage spreads the directive over this window, by a per-host offset, so many VMs behind one
  # address do not start downloading together and hit the release download limit (60 a minute per address by
  # default, at least three requests per update). 300 seconds fits about 100 hosts per address.
  rollouts.spread ||= Integer(ENV.fetch("FLEET_ROLLOUT_SPREAD_SECONDS", "300")).clamp(1..)

  # A large stage spreads over a longer window, so its hosts download at most about this many releases a second on
  # average (#199): the window is the larger of the spread above and the stage's hosts divided by this. At the
  # default a homelab stage keeps the 300 seconds; 75,000 hosts take about 2 hours.
  # A whole number from 1 to 100,000; anything else stops the server from starting.
  rollouts.downloads_per_second ||= begin
    value = ENV.fetch("FLEET_ROLLOUT_DOWNLOADS_PER_SECOND", "10")
    rate = Integer(value, 10, exception: false)
    raise "FLEET_ROLLOUT_DOWNLOADS_PER_SECOND must be a whole number of downloads a second from 1 to 100000 (got #{value.inspect})" unless rate&.between?(1, 100_000)

    rate
  end

  # From this many active hosts a rollout's default stages are 1, 10, 50, and 100 percent rather than 25 and 100
  # (Rollouts.default_stages, #199). A whole number from 1 to 100,000,000; anything else stops the server from
  # starting, rather than silently choosing other stages.
  rollouts.large_fleet_hosts ||= begin
    value = ENV.fetch("FLEET_ROLLOUT_LARGE_FLEET_HOSTS", "1000")
    hosts = Integer(value, 10, exception: false)
    raise "FLEET_ROLLOUT_LARGE_FLEET_HOSTS must be a whole number of hosts from 1 to 100000000 (got #{value.inspect})" unless hosts&.between?(1, 100_000_000)

    hosts
  end

  # A host that was sent the directive and has not reported a result within this long is marked unconfirmed,
  # which halts the rollout. The agent's own rollback deadline is 5 minutes (ADR 0018).
  rollouts.confirmation_timeout ||= Integer(ENV.fetch("FLEET_UPDATE_CONFIRMATION_TIMEOUT_MINUTES", "30")).clamp(1..).minutes

  # Once every host of a stage has confirmed, the stage stays open this long before the next one opens, or the last one
  # completes the rollout (#251, owner decision 2026-11-23, ADR 0018): restarts keep counting meanwhile, so a release
  # that leaks slowly halts at the canaries, not after the whole fleet has it. An operator's Advance does not wait. A
  # whole number of minutes from 0 (no observation) to 10,080 (a week); anything else stops the server from starting.
  rollouts.stage_observe ||= begin
    value = ENV.fetch("FLEET_ROLLOUT_STAGE_OBSERVE_MINUTES", "30")
    minutes = Integer(value, 10, exception: false)
    raise "FLEET_ROLLOUT_STAGE_OBSERVE_MINUTES must be a whole number of minutes from 0 to 10080 (got #{value.inspect})" unless minutes&.between?(0, 10_080)

    minutes.minutes
  end

  # A restart loop (#251, ADR 0018): an agent that systemd restarted more than restart_limit times within
  # restart_window. A host in a rollout that does so after it was sent the update counts as failed for its stage, which
  # halts the rollout (owner, 2026-11-23: 3 times in 24 hours), and the fleet list's "Restarted" filter lists the hosts
  # that did so. Whole numbers: restarts from 1 to 31 (the hosts row keeps the last 32 restarts, Liveness::RESTART_HISTORY),
  # hours from 1 to 168; anything else stops the server from starting.
  restart_loop = config.x.restart_loop
  restart_loop.limit ||= begin
    value = ENV.fetch("FLEET_RESTART_LOOP_RESTARTS", "3")
    limit = Integer(value, 10, exception: false)
    raise "FLEET_RESTART_LOOP_RESTARTS must be a whole number of restarts from 1 to 31 (got #{value.inspect})" unless limit&.between?(1, 31)

    limit
  end
  restart_loop.window ||= begin
    value = ENV.fetch("FLEET_RESTART_LOOP_WINDOW_HOURS", "24")
    hours = Integer(value, 10, exception: false)
    raise "FLEET_RESTART_LOOP_WINDOW_HOURS must be a whole number of hours from 1 to 168 (got #{value.inspect})" unless hours&.between?(1, 168)

    hours.hours
  end
end
