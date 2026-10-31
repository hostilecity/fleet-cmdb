# The fleet-wide audit log page (FR-S.3, P1-AUDIT-PAGE). Built from query parameters so every view can be
# bookmarked: actor_type, actor (email, host name, or hostname), action, target (host name or hostname,
# retired hosts included), host_id (one exact host, from the host page), from and to (whole UTC days, both
# included), hide_sign_ins, and one keyset cursor, before or after.
#
# Read-only: this only ever reads AuditEntry. Pages are keyset ranges on (occurred_at, id), newest first, so
# a page costs the same however long the log grows; there are no page numbers or total count.
#
# Onboarding approvals and rejections target the request, not a host. A request is linked to a host by the
# log itself, because requests are pruned a day after they expire: the host's "Enrolled" entry names the
# request it collected, and a re-enrollment approval names the host it re-enrolls. Filtering by a host
# includes those requests' entries.
class AuditLog
  PER_PAGE = 50
  PARAMS = %i[actor_type actor action target host_id from to hide_sign_ins before after].freeze
  ACTOR_TYPES = { "operator" => "Operator", "host" => "Host", "system" => "System" }.freeze
  MAX_TEXT = 254 # the longest email or hostname
  MATCH_LIMIT = 500
  DATE_FORMAT = /\A\d{4}-\d{2}-\d{2}\z/
  ID_FORMAT = /\A[1-9]\d{0,17}\z/ # a positive bigint, without leading zeros
  # Readable: the entry's occurred_at in UTC to the microsecond, a comma, and its id.
  CURSOR_FORMAT = /\A(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z),([1-9]\d{0,17})\z/
  KEY = "(audit_entries.occurred_at, audit_entries.id)"
  NEWEST_FIRST = [ Arel.sql("audit_entries.occurred_at DESC"), Arel.sql("audit_entries.id DESC") ].freeze
  OLDEST_FIRST = [ Arel.sql("audit_entries.occurred_at ASC"), Arel.sql("audit_entries.id ASC") ].freeze

  # The changeset paths that link an onboarding request and a host. Each has a partial expression index
  # (db/migrate/20261030010000_index_audit_entries_onboarding_links.rb).
  ENROLLED_REQUEST = "(audit_entries.changeset #>> '{onboarding_request_id,1}')"
  APPROVED_HOST = "(audit_entries.changeset #>> '{host_id,1}')"

  Cursor = Data.define(:occurred_at, :id) do
    # A Cursor, or nil when value is not one (malformed, an impossible time, or out of range).
    def self.parse(value)
      match = CURSOR_FORMAT.match(value.to_s) or return nil
      time = Time.iso8601(match[1])
      # Time.iso8601 rolls 30 February over to 2 March; a cursor this page wrote always reads back the same.
      return nil unless time.strftime("%Y-%m-%dT%H:%M:%S") == match[1][0, 19]

      new(occurred_at: time, id: Integer(match[2], 10))
    rescue ArgumentError
      nil
    end

    def self.of(entry) = new(occurred_at: entry.occurred_at, id: entry.id)

    def to_param = "#{occurred_at.utc.strftime('%Y-%m-%dT%H:%M:%S.%6N')}Z,#{id}"
  end

  # entries: newest first. newer and older: the cursor parameters for the neighbouring pages, or nil.
  Page = Data.define(:entries, :newer, :older)

  # What the page shows for the entries' actors and targets, loaded in a fixed number of queries however
  # many entries there are. Records may be gone (a removed allowlist entry, a pruned onboarding request);
  # the page then shows what the entry itself recorded.
  Records = Data.define(:operators, :hosts, :requests, :request_hosts, :settings, :allowlist) do
    def self.for(entries)
      ids = ->(type, kind) { entries.filter_map { |e| e.public_send(:"#{kind}_id") if e.public_send(:"#{kind}_type") == type }.uniq }
      request_ids = ids.("OnboardingRequest", :target)
      request_hosts = AuditLog.hosts_for_requests(request_ids)
      operator_ids = ids.("operator", :actor) | ids.("Operator", :target)
      host_ids = ids.("host", :actor) | ids.("Host", :target) | request_hosts.values
      setting_ids = ids.("Setting", :target)
      allowlist_ids = ids.("OperatorAllowlistEntry", :target)
      new(
        operators: operator_ids.any? ? Operator.where(id: operator_ids).index_by(&:id) : {},
        hosts: host_ids.any? ? Host.where(id: host_ids).index_by(&:id) : {},
        requests: request_ids.any? ? OnboardingRequest.where(id: request_ids).index_by(&:id) : {},
        request_hosts:,
        settings: setting_ids.any? ? Setting.where(id: setting_ids).pluck(:id, :key).to_h : {},
        allowlist: allowlist_ids.any? ? OperatorAllowlistEntry.where(id: allowlist_ids).pluck(:id, :email).to_h : {}
      )
    end
  end

  attr_reader :actor_type, :actor, :action, :target, :host_id, :from, :to, :errors

  def initialize(params = {})
    @actor_type = ACTOR_TYPES.key?(params[:actor_type]) ? params[:actor_type] : nil
    @actor = text(params[:actor]) unless @actor_type == "system" # the system has no name to match
    @action = Audit::Actions::ALL.include?(params[:action]) ? params[:action] : nil
    @target = text(params[:target])
    @host_id = params[:host_id].to_s.match?(ID_FORMAT) ? params[:host_id].to_i : nil
    @hide_sign_ins = params[:hide_sign_ins] == "1"
    @errors = {}
    @raw_from = params[:from].to_s.strip.presence
    @raw_to = params[:to].to_s.strip.presence
    @from = date(:from, @raw_from)
    @to = date(:to, @raw_to)
    @before = params[:before].presence
    @after = params[:after].presence
  end

  def valid? = errors.empty?

  # Sign-ins are hidden only while no action is chosen: choosing an action shows exactly that action.
  def hide_sign_ins? = @hide_sign_ins && action.nil?

  def filtered? = filter_params.except(:hide_sign_ins).any?

  # The date as typed, for redisplay when it is invalid.
  def raw(field) = field == :from ? @raw_from : @raw_to

  # The filters, without blanks, for links that keep them (pages, the sign-in toggle).
  def filter_params
    { actor_type:, actor:, action:, target:, host_id:, from: @raw_from, to: @raw_to,
      hide_sign_ins: (@hide_sign_ins ? "1" : nil) }.compact
  end

  # The cursor parameter was present but is not a valid position: malformed, tampered with, or both
  # before and after at once. The page then starts from the newest entry.
  def invalid_cursor?
    return false if @before.nil? && @after.nil?

    (@before && @after) || cursor.nil?
  end

  # The host for host_id, or nil when there is none (the filter then matches nothing).
  def host
    return @host if defined?(@host)

    @host = host_id && Host.find_by(id: host_id)
  end

  def page
    return Page.new(entries: [], newer: nil, older: nil) unless valid?

    if !invalid_cursor? && @after
      newer_page(cursor)
    else
      older_page(invalid_cursor? ? nil : cursor)
    end
  end

  # Every matching entry, in no particular order.
  def scope
    scope = AuditEntry.all
    scope = filter_actor(scope)
    scope = scope.where(action:) if action
    scope = scope.where.not(action: Audit::Actions::OPERATOR_SIGNED_IN) if hide_sign_ins?
    scope = scope.where(self.class.for_hosts_sql(ids_or_query(hosts_named(target)))) if target
    scope = scope.where(self.class.for_hosts_sql([ host_id ])) if host_id
    scope = scope.where(occurred_at: from.beginning_of_day.utc..) if from
    scope = scope.where(occurred_at: ...(to + 1).beginning_of_day.utc) if to
    scope
  end

  # SQL matching entries that target one of the hosts, or an onboarding request linked to one of them.
  # hosts: an array of host ids, or (for a filter matching very many hosts) a relation selecting hosts.id.
  def self.for_hosts_sql(hosts)
    quote = AuditEntry.connection.method(:quote)
    if hosts.is_a?(Array)
      return "FALSE" if hosts.empty?

      ids = hosts.map { |id| Integer(id) }.join(", ")
      requests = collected_requests(hosts).join(", ").presence || "NULL"
      approved_hosts = hosts.map { |id| quote.(id.to_s) }.join(", ")
    else
      ids = hosts.to_sql
      request = ENROLLED_REQUEST.sub("audit_entries.", "enrolled.")
      requests = "SELECT #{request}::bigint FROM audit_entries enrolled WHERE enrolled.action = #{quote.(Audit::Actions::HOST_ENROLLED)} " \
                 "AND enrolled.target_type = 'Host' AND enrolled.target_id IN (#{ids}) AND #{request} ~ '^[1-9][0-9]{0,17}$'"
      approved_hosts = "SELECT matched.id::text FROM (#{ids}) matched"
    end
    <<~SQL.squish
      (audit_entries.target_type = 'Host' AND audit_entries.target_id IN (#{ids}))
      OR (audit_entries.target_type = 'OnboardingRequest' AND audit_entries.target_id IN (#{requests}))
      OR (audit_entries.action = #{quote.(Audit::Actions::ONBOARDING_APPROVED)} AND #{APPROVED_HOST} IN (#{approved_hosts}))
    SQL
  end

  # The onboarding requests the hosts collected, from their "Enrolled" entries.
  def self.collected_requests(host_ids)
    AuditEntry.where(action: Audit::Actions::HOST_ENROLLED, target_type: "Host", target_id: host_ids)
      .where("#{ENROLLED_REQUEST} ~ '^[1-9][0-9]{0,17}$'").distinct.pluck(Arel.sql(ENROLLED_REQUEST)).map(&:to_i)
  end

  # { request id => host id } for the onboarding requests, from the log (see the class comment). A
  # collection wins over the approval: it is what the request became.
  def self.hosts_for_requests(request_ids)
    return {} if request_ids.empty?

    keys = request_ids.map(&:to_s)
    approved = AuditEntry.where(action: Audit::Actions::ONBOARDING_APPROVED, target_type: "OnboardingRequest", target_id: request_ids)
      .where("#{APPROVED_HOST} ~ '^[1-9][0-9]{0,17}$'").pluck(:target_id, Arel.sql(APPROVED_HOST))
    collected = AuditEntry.where(action: Audit::Actions::HOST_ENROLLED, target_type: "Host")
      .where("#{ENROLLED_REQUEST} IN (?)", keys).pluck(Arel.sql(ENROLLED_REQUEST), :target_id)
    approved.to_h { |request, host| [ request, host.to_i ] }.merge(collected.to_h { |request, host| [ request.to_i, host ] })
  end

  private

  def cursor = (@cursor = defined?(@cursor) ? @cursor : Cursor.parse(@before || @after))

  # Entries older than the cursor (or the newest), newest first.
  def older_page(position)
    rows = scope
    rows = rows.where("#{KEY} < (?, ?)", position.occurred_at, position.id) if position
    rows = rows.order(*NEWEST_FIRST).limit(PER_PAGE + 1).to_a
    entries = rows.first(PER_PAGE)
    Page.new(entries:, newer: position && newer_link(entries, position), older: rows.size > PER_PAGE ? { before: Cursor.of(entries.last).to_param } : nil)
  end

  # The way back from a page reached with a cursor: the entries newer than its first, or, from a cursor
  # past the oldest entry (only a hand-made link), the first page.
  def newer_link(entries, position)
    if entries.any?
      first = entries.first
      { after: Cursor.of(first).to_param } if scope.where("#{KEY} > (?, ?)", first.occurred_at, first.id).exists?
    elsif scope.where("#{KEY} >= (?, ?)", position.occurred_at, position.id).exists?
      {}
    end
  end

  # Entries newer than the cursor, newest first. When they reach the newest entry this is the first page,
  # so going back always ends on a full first page.
  def newer_page(position)
    rows = scope.where("#{KEY} > (?, ?)", position.occurred_at, position.id).order(*OLDEST_FIRST).limit(PER_PAGE + 1).to_a
    return older_page(nil) if rows.size <= PER_PAGE

    entries = rows.first(PER_PAGE).reverse
    Page.new(entries:, newer: { after: Cursor.of(entries.first).to_param }, older: { before: Cursor.of(entries.last).to_param })
  end

  def filter_actor(scope)
    case actor_type
    when "system" then scope.where(actor_type: "system")
    when "operator" then scope.where(actor_type: "operator").then { |s| actor ? s.where(actor_id: ids_or_query(operators_named(actor))) : s }
    when "host" then scope.where(actor_type: "host").then { |s| actor ? s.where(actor_id: ids_or_query(hosts_named(actor))) : s }
    else
      return scope unless actor

      scope.where(actor_type: "operator", actor_id: ids_or_query(operators_named(actor)))
        .or(scope.where(actor_type: "host", actor_id: ids_or_query(hosts_named(actor))))
    end
  end

  # The matching ids, so the planner sees how many there are and picks the right index; or, past
  # MATCH_LIMIT, the query itself, since so broad a match is quickest found walking the log by time.
  def ids_or_query(relation)
    ids = relation.limit(MATCH_LIMIT + 1).pluck(:id)
    ids.size > MATCH_LIMIT ? relation : ids
  end

  # Case-insensitive substring matches, as in the fleet search (FleetList). Retired hosts are included.
  def hosts_named(text) = Host.where("hosts.name ILIKE :p OR hosts.hostname ILIKE :p", p: like(text)).select(:id)

  def operators_named(text) = Operator.where("operators.email ILIKE :p", p: like(text)).select(:id)

  def like(text) = "%#{ActiveRecord::Base.sanitize_sql_like(text)}%"

  def text(value) = value.to_s.squish.first(MAX_TEXT).presence

  def date(field, value)
    return nil if value.nil?

    # A date input cannot show a value it does not understand, so the message repeats what was given.
    shown = value.first(20)
    parsed = value.match?(DATE_FORMAT) ? Date.strptime(value, "%Y-%m-%d") : nil
    errors[field] = "“#{shown}” is not a date. Enter one as YYYY-MM-DD." unless parsed
    parsed
  rescue Date::Error
    errors[field] = "“#{shown}” is not a real date. Enter one as YYYY-MM-DD."
    nil
  end
end
