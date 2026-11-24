module FindingDecisions
  # Rule O1's adapter (VulnerabilityTriage::HostFacts.control_source, set in config/initializers/finding_decisions.rb):
  # the advisories each host has a control in force for, active and not past its last day, read by the partial
  # unique index on the active decisions. A suspended, ended, or lapsed control is not in force, so the finding falls
  # through to the rules after O1.
  module ControlSource
    module_function

    # { host id => Set of advisory ids }.
    def controls(host_ids, now:)
      return {} if host_ids.empty?

      FindingDecision.in_force(now.to_date).where(host_id: host_ids, kind: "control").pluck(:host_id, :advisory_id)
                     .group_by(&:first).transform_values { |rows| rows.to_set(&:last) }
    end
  end
end
