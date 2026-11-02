module Releases
  # Whether the release files the fleet depends on are on disk (P1-S11 /health, P1-O01): the newest
  # release's binary, and the binary of the release a running rollout is sending out, must exist with the size
  # their rows record. An existence and size check only, never a scan of the directory or a re-hash. Rows of a
  # restored database whose files did not come back, or a volume that was mounted empty, show up here.
  module StoreCheck
    module_function

    # The versions whose binary is missing or has the wrong size.
    def problems(store: Releases.store)
      targets.reject { |release| File.size?(store.path(release.version, release.target)) == release.size }.map(&:version)
    end

    def healthy?(store: Releases.store) = problems(store:).empty?

    # The newest release and the target of the running rollout (a halted rollout sends nothing), each once.
    def targets
      rollout_release = Rollout.where(state: "running").includes(:agent_release).first&.agent_release
      [ AgentRelease.newest_first.first, rollout_release ].compact.uniq
    end
  end
end
