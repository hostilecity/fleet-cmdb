# Agent rollouts (P1-UPDATES, ADR 0018). Environment files may set any of these first; tests do.
Rails.application.configure do
  rollouts = config.x.rollouts

  # Opening a stage spreads the directive over this window, by a per-host offset, so many VMs behind one
  # address do not start downloading together and hit the release download limit (60 a minute per address by
  # default, at least three requests per update). 300 seconds fits about 100 hosts per address.
  rollouts.spread ||= Integer(ENV.fetch("FLEET_ROLLOUT_SPREAD_SECONDS", "300")).clamp(1..)

  # A host that was sent the directive and has not reported a result within this long is marked unconfirmed,
  # which halts the rollout. The agent's own rollback deadline is 5 minutes (ADR 0018).
  rollouts.confirmation_timeout ||= Integer(ENV.fetch("FLEET_UPDATE_CONFIRMATION_TIMEOUT_MINUTES", "30")).clamp(1..).minutes
end
