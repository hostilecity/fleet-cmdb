# On-demand reports (P2-S03, FR-2.1, DEC-13, DEC-20). The only code that changes a ReportRequest.
#
# - request! records an operator's request for fresh reports of some types from one host, audited as
#   host.report_requested. It is the action behind the host page's "Request fresh reports" button (P2-D02).
# - directive_for builds the heartbeat's report_request directive, {"types": [...]}, from the host's
#   outstanding requests. It is sent on every heartbeat until each request is satisfied or expires, so a lost
#   response or an agent restart cannot drop a request. An agent that predates the directive ignores the name
#   (DEC-20 rule 4) and keeps reporting on its own schedule; such a report satisfies the request all the same.
# - satisfy! is called by InventoryRecorder, PackageRecorder, and ConfigRecorder, under the host row lock, for
#   every new (not duplicate) report: it clears the host's pending request of that type when the report was
#   collected after the request. A report whose content did not change still counts: the operator asked for a
#   fresh report, not for a change.
# - expire! (run every minute by ReportRequestExpiryJob) marks requests never satisfied within TTL as
#   expired, with expired_at. They are kept, not deleted, so the host page can say the agent never answered.
#
# Rate limit: one request per host and report type per COOLDOWN, whatever happened to the previous one, so
# repeated clicks (or a script) cannot make an agent collect a report over and over. A type that is still
# pending from an earlier request older than COOLDOWN is left as it is (it is already in the directive).
# The check runs under the host row lock, and a partial unique index allows one pending request per host and
# type, so concurrent requests cannot both create one.
#
# Clock skew. requested_at is the server clock; a report's collected_at is the agent's clock (DEC-07: the agent
# clock is never trusted for liveness). Comparing them directly would break both ways: an agent clock behind
# the server's would make every fresh report look older than the request, so the request would never clear and
# the agent would be asked again on every heartbeat until it expired; a clock ahead would let a report collected
# before the request clear it. So collected_at is first moved onto the server clock with the offset the host's
# last heartbeat measured (agent_reported_at minus last_seen_at, both stored by Liveness on every heartbeat). That
# offset also includes the heartbeat's one-way latency and the agent's timestamps being whole seconds, so a
# report collected up to about a second before the request can count as after it, which is harmless: the
# directive reaches the agent only after the request, so a report it causes is always later. A host with no
# heartbeat yet uses no offset. Received time (server clock) alone is not used: a report collected before the request but delivered
# after it (a retry after a network failure) is not the fresh report the operator asked for.
module ReportRequests
  TTL = 1.hour
  COOLDOWN = 5.minutes

  # The host is not active, so its agent cannot heartbeat and would never see the request.
  class NotActive < StandardError; end
  # The request named no known report type.
  class NoTypes < StandardError; end

  # requested: types given a new request. outstanding: types already pending from an earlier request.
  # rate_limited: types requested within COOLDOWN, and retry_at, when the first of them may be requested again.
  Result = Data.define(:requested, :outstanding, :rate_limited, :retry_at)

  module_function

  # Raises NoTypes when types names no known report type, and NotActive for a host that is not active.
  def request!(host:, types:, actor:, now: Time.current)
    types = ReportRequest::TYPES & Array(types).map(&:to_s)
    raise NoTypes if types.empty?

    Host.transaction do
      host = Host.lock.find(host.id) # serialises requests for one host, and a concurrent revoke or retire
      raise NotActive unless host.enrollment_state == "active"

      expire!(now:, host_id: host.id) # a pending request past its expiry must not block a new one
      requests = ReportRequest.where(host_id: host.id, report_type: types)
      latest = requests.group(:report_type).maximum(:requested_at)
      pending = requests.pending.pluck(:report_type)
      rate_limited = types.select { |type| latest[type] && latest[type] > now - COOLDOWN }
      outstanding = (types & pending) - rate_limited
      requested = types - rate_limited - outstanding
      record!(host, requested, actor, now) if requested.any?
      Result.new(requested:, outstanding:, rate_limited:, retry_at: rate_limited.map { |type| latest[type] + COOLDOWN }.min)
    end
  end

  # The report_request directive for a heartbeat, or nil when nothing is outstanding. Marks the requests a
  # heartbeat carries for the first time as sent. Runs in the heartbeat's transaction, under the host row lock.
  # A host with nothing outstanding costs one indexed SELECT and no write.
  def directive_for(host_id:, now: Time.current)
    rows = ReportRequest.outstanding(now).where(host_id:).pluck(:id, :report_type, :sent_at)
    return nil if rows.empty?

    unsent = rows.filter_map { |id, _type, sent_at| id if sent_at.nil? }
    ReportRequest.where(id: unsent).update_all(sent_at: now) if unsent.any?
    { types: ReportRequest::TYPES & rows.map(&:second) }
  end

  # Clears the host's pending request of report_type if report was collected after it (see "Clock skew"
  # above). host is the row AgentHostLock locked. A late report still satisfies a request that expired by time
  # but that ReportRequestExpiryJob has not marked yet. Returns the number of requests cleared (0 or 1).
  def satisfy!(host:, report_type:, report:, now: Time.current)
    collected = report.collected_at - clock_offset(host)
    ReportRequest.pending.where(host_id: host.id, report_type:).where(requested_at: ...collected)
                 .update_all(state: "satisfied", satisfied_at: now, satisfied_by_report_id: report.report_id)
  end

  # Marks pending requests past their expiry as expired, for one host or all. Returns how many.
  def expire!(now: Time.current, host_id: nil)
    scope = ReportRequest.pending.where(expires_at: ..now)
    scope = scope.where(host_id:) if host_id
    scope.update_all(state: "expired", expired_at: now)
  end

  # How far the agent's clock is ahead of the server's (negative when behind), as the last heartbeat saw it.
  def clock_offset(host)
    return 0 unless host.agent_reported_at && host.last_seen_at

    host.agent_reported_at - host.last_seen_at
  end

  def record!(host, types, actor, now)
    expires_at = now + TTL
    ReportRequest.insert_all!(types.map do |report_type|
      { host_id: host.id, report_type:, requested_by_id: actor.id, requested_at: now, expires_at: }
    end)
    Audit.record(actor:, action: Audit::Actions::HOST_REPORT_REQUESTED, target: host, changes: { "report_types" => [ nil, types ] })
  end
  private_class_method :clock_offset, :record!
end
