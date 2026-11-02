module Releases
  # Whether the release files the fleet depends on are on disk (P1-S11 /health, P1-O01): the newest
  # release's binary must exist with the size its row records. An existence and size check only, never a
  # scan of the directory or a re-hash. Rows of a restored database whose files did not come back, or a
  # volume that was mounted empty, show up here. A running rollout's target joins the list with P1-UPDATES.
  module StoreCheck
    module_function

    # The versions whose binary is missing or has the wrong size.
    def problems(store: Releases.store)
      targets.reject { |release| File.size?(store.path(release.version, release.target)) == release.size }.map(&:version)
    end

    def healthy?(store: Releases.store) = problems(store:).empty?

    def targets = [ AgentRelease.newest_first.first ].compact
  end
end
