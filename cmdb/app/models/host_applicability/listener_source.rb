class HostApplicability
  # VT-BUCKETS' listener hook (VulnerabilityTriage::HostFacts.listener_source, rule N5; owner decision 2026-11-21),
  # over host_applicability: for each host whose latest scan the server received less than LISTENER_FRESH ago, every
  # package a process holding a listening socket loads, as a VulnerabilityTriage::Listener. Set in
  # config/initializers/vulnerability_triage.rb.
  module ListenerSource
    module_function

    # { host id => { package => Listener } } of the hosts with current evidence. package_sets (each host's triaged
    # package set) is not needed: the evidence names packages, and HostFacts looks each finding's package up.
    def listeners(host_ids, package_sets:, now:)
      _ = package_sets
      current(now).where(host_id: host_ids).to_h { |row| [ row.host_id, row.listener_evidence ] }
    end

    # The hosts with evidence whose scan the server received in (from, to], for TriageListenerExpiryJob: their N5
    # findings fall back to the rules without it. Uses the index on library_scan_received_at.
    def listener_hosts_expiring(from:, to:)
      with_evidence.where("library_scan_received_at > ? AND library_scan_received_at <= ?", from, to).pluck(:host_id)
    end

    def current(now) = with_evidence.where("library_scan_received_at > ?", now - VulnerabilityTriage::LISTENER_FRESH)

    def with_evidence = HostApplicability.where(library_scan: "ran").where("jsonb_array_length(loaded_by_listeners) > 0")
  end
end
