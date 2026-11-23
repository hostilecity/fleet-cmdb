class HostApplicability
  # VT-BUCKETS' listener hook (VulnerabilityTriage::HostFacts.listener_source, rule N5; owner decision 2026-11-21),
  # over host_applicability: for each host whose latest scan the server received less than LISTENER_FRESH ago, every
  # package a process holding a listening socket loads, as a VulnerabilityTriage::Listener. Set in
  # config/initializers/vulnerability_triage.rb.
  module ListenerSource
    module_function

    # { host id => { package => Listener } } of the hosts with current evidence. HostFacts also passes package_sets:
    # (each host's triaged package set), taken by ** and unused: the evidence names packages, and HostFacts looks each
    # finding's package up.
    def listeners(host_ids, now:, **)
      current(now).where(host_id: host_ids).to_h { |row| [ row.host_id, row.listener_evidence ] }
    end

    # The hosts with evidence whose scan the server received in (from, to], for TriageListenerExpiryJob: their N5
    # findings fall back to the rules without it. Uses the partial index on library_scan_received_at, whose condition
    # is with_evidence's.
    def listener_hosts_expiring(from:, to:)
      with_evidence.where("library_scan_received_at > ? AND library_scan_received_at <= ?", from, to).pluck(:host_id)
    end

    # Why a host's findings can or cannot be escalated by N5 now, for the host tab (VT-HOST-TAB #260), in one query:
    # :not_reported (no in-use report: an agent that predates #258, an unreadable or unsupported package report),
    # :scan_off (the library scan is off on the VM, its default), :scan_failed, :kernel_too_old (the scan ran on a
    # kernel before Linux 5.14: loaded_by_listeners NULL), :expired (the scan is older than LISTENER_FRESH), or :known.
    def coverage(host_id, now:)
      row = HostApplicability.find_by(host_id:)
      return :not_reported unless row&.in_use_reported
      return :scan_off if row.library_scan == "off"
      return :scan_failed if row.library_scan == "failed"
      return :kernel_too_old unless row.listeners_known?

      row.library_scan_received_at && row.library_scan_received_at > now - VulnerabilityTriage::LISTENER_FRESH ? :known : :expired
    end

    def current(now) = with_evidence.where("library_scan_received_at > ?", now - VulnerabilityTriage::LISTENER_FRESH)

    def with_evidence = HostApplicability.where(library_scan: "ran").where("jsonb_array_length(loaded_by_listeners) > 0")
  end
end
