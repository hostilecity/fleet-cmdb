# A host's Configuration tab and config snapshot comparison (P2-D02, FR-2.2, FR-2.5; approved mockups host-config.html
# and host-config-diff.html). Read-only: the request button posts to HostActionsController#request_reports.
#
# - CIS-aligned results per rule, grouped by area (ConfigArea), filterable by result (default "Needs attention": fail
#   and not readable, owner decision Q4), severity, and text; the pass rate (CisCompliance, Q3).
# - The latest facts, grouped by area: by default the ones a rule inspects or that are not OK, ?facts=all for every one.
# - Config snapshots, each with what changed and the check results it flipped, and result change history with the
#   cause of each change (CisResultHistory).
# - compare: any two snapshots, ?from=&to= (snapshot ids), on its own page (Q5); by default the latest against the one
#   before it.
class HostConfigsController < ApplicationController
  include HostTab

  RESULT_FILTERS = %w[attention fail not_readable pass not_applicable not_evaluated all].freeze
  ATTENTION = %w[fail not_readable].freeze
  RESULT_ORDER = %w[fail not_readable pass not_applicable not_evaluated].freeze
  SEVERITY_ORDER = %w[critical high medium low].freeze
  SNAPSHOT_LIMIT = 25
  HISTORY_LIMIT = 5
  HISTORY_ALL_LIMIT = 200
  QUERY_MAX = 100

  # One rule on this host: its current result (not evaluated when it has none yet) and the rule version shown.
  Check = Data.define(:rule, :version, :result, :observed, :reason) do
    def area = ConfigArea.of(version.fact)
    def attention? = ATTENTION.include?(result)
  end

  before_action :load_host_tab

  def show
    @config = HostConfig.find_by(host_id: @host.id)
    @availability = ReportRequests.availability(host: @host).fetch("config")
    @latest_snapshot = ConfigSnapshot.where(host_id: @host.id).order(received_at: :desc, id: :desc).first
    load_checks
    load_facts
    load_snapshots
    @history = CisResultHistory.new(@host.id).latest(params[:history] == "all" ? HISTORY_ALL_LIMIT : HISTORY_LIMIT + 1)
  end

  def compare
    snapshots = ConfigSnapshot.where(host_id: @host.id).order(received_at: :desc, id: :desc).select(:id, :received_at).to_a
    @snapshot_count = snapshots.size
    # A named snapshot must be this host's, even when there is nothing to compare (review of #118).
    named = params.values_at(:from, :to).select(&:present?)
    raise ActiveRecord::RecordNotFound, "no such config snapshot for this host" unless named.all? { |id| snapshots.any? { |s| s.id.to_s == id } }
    return if snapshots.size < 2

    @to = params[:to].present? ? snapshots.find { |s| s.id.to_s == params[:to] } : snapshots.first
    @from = params[:from].present? ? snapshots.find { |s| s.id.to_s == params[:from] } : snapshots[snapshots.index(@to).to_i + 1]
    raise ActiveRecord::RecordNotFound, "no such config snapshot for this host" unless @from && @to

    @pickable = picker_snapshots(snapshots)
    load_comparison(snapshots)
  end

  private

  def load_checks
    rules = CisRule.includes(:current_version).order(:key).to_a.select(&:current_version)
    results = CisResult.where(host_id: @host.id).includes(:cis_rule_version).index_by(&:cis_rule_id)
    @checks = rules.map do |rule|
      result = results[rule.id]
      Check.new(rule:, version: result&.cis_rule_version || rule.current_version, result: result&.result || "not_evaluated",
                observed: result&.observed, reason: result ? result.reason : "The rule has not been evaluated on this host yet.")
    end
    @result_counts = @checks.map(&:result).tally
    @result_filter = RESULT_FILTERS.include?(params[:result]) ? params[:result] : "attention"
    @severity = SEVERITY_ORDER.include?(params[:severity]) ? params[:severity] : nil
    @query = params[:q].to_s.strip.first(QUERY_MAX)
    @shown_checks = @checks.select { |check| show_check?(check) }.sort_by do |check|
      [ RESULT_ORDER.index(check.result), SEVERITY_ORDER.index(check.version.severity) || 9, check.rule.key ]
    end
  end

  def show_check?(check)
    by_result = case @result_filter
    when "attention" then check.attention?
    when "all" then true
    else check.result == @result_filter
    end
    by_result && (@severity.nil? || check.version.severity == @severity) &&
      (@query.empty? || [ check.version.title, check.rule.key, check.version.reference, check.version.fact ].any? { |text| text.downcase.include?(@query.downcase) })
  end

  def load_facts
    facts = @config&.facts || {}
    @rule_facts = @checks.map { |check| check.rule.current_version.fact }.to_set
    @all_facts = params[:facts] == "all"
    @fact_total = facts.size
    @fact_counts = facts.values.map { |fact| fact["state"] }.tally
    @shown_facts = @all_facts ? facts : facts.select { |key, fact| fact["state"] != "ok" || @rule_facts.include?(key) }
  end

  # The newest snapshots, each with the diff from the one before it and the result changes it produced.
  def load_snapshots
    rows = ConfigSnapshot.where(host_id: @host.id).order(received_at: :desc, id: :desc).limit(SNAPSHOT_LIMIT + 1).to_a
    @more_snapshots = rows.size > SNAPSHOT_LIMIT
    changes = CisResultHistory.new(@host.id).for_snapshots(rows.first(SNAPSHOT_LIMIT).map(&:id)).group_by(&:snapshot_id)
    @snapshots = rows.first(SNAPSHOT_LIMIT).each_with_index.map do |snapshot, i|
      previous = rows[i + 1]
      first = previous.nil? && !@more_snapshots
      { snapshot:, previous:, first:, diff: (ConfigDiff.between(previous, snapshot) if previous),
        flips: Array(changes[snapshot.id]).select { |entry| entry.cause.in?(%i[report first]) && !entry.from.nil? } }
    end
  end

  # The snapshots the pickers offer: every snapshot kept, so older history can be chosen without knowing its id
  # (review of #118). Only the newest SNAPSHOT_LIMIT and the compared pair are labelled with how many facts
  # changed, so the facts loaded stay bounded.
  def picker_snapshots(snapshots)
    labels = snapshot_change_counts(snapshots.first(SNAPSHOT_LIMIT) | [ @from, @to ])
    snapshots.map { |s| [ s, labels[s.id], s == snapshots.first, s == snapshots.last ] }
  end

  # { snapshot id => facts changed since the one before it } for the given snapshots.
  def snapshot_change_counts(chosen)
    order = ConfigSnapshot.where(host_id: @host.id).order(:received_at, :id).pluck(:id)
    previous = chosen.to_h { |s| [ s.id, (i = order.index(s.id)).positive? ? order[i - 1] : nil ] }
    facts = ConfigSnapshot.where(id: chosen.map(&:id) + previous.values.compact).pluck(:id, :facts).to_h
    chosen.to_h { |s| [ s.id, previous[s.id] && ConfigDiff.between(facts[previous[s.id]], facts[s.id]).then { |d| d.changed.size + d.added.size + d.removed.size } ] }
  end

  def load_comparison(snapshots)
    older, newer = [ @from, @to ].sort_by { |s| [ s.received_at, s.id ] }
    @reversed = older != @from
    facts = ConfigSnapshot.where(id: [ @from.id, @to.id ]).pluck(:id, :facts).to_h
    @diff = ConfigDiff.between(facts[@from.id], facts[@to.id])
    range_ids = snapshots.select { |s| ([ s.received_at, s.id ] <=> [ older.received_at, older.id ]).positive? && ([ s.received_at, s.id ] <=> [ newer.received_at, newer.id ]) <= 0 }.map(&:id)
    history = CisResultHistory.new(@host.id)
    reports = history.for_snapshots(range_ids).select { |entry| entry.cause == :report }
    @rule_changes = history.during(older.received_at..newer.received_at).reject { |entry| entry.cause.in?(%i[report first]) }
    changed_facts = @diff.changed.map(&:key) + @diff.added.keys + @diff.removed.keys
    @effects = net_effects(reports, @rule_changes).slice(*changed_facts)
  end

  # { fact key => [[rule key, from, to], ...] }: the results each changed fact's reports flipped, in the direction
  # compared. A rule's report changes are joined only while no rule edit, enable, or disable comes between them, so
  # a result a rule change explains is never shown as a report's effect (review of #118); a stretch that ended
  # where it started is left out.
  def net_effects(reports, rule_changes)
    (reports + rule_changes).sort_by { |entry| [ entry.occurred_at, entry.change.id ] }.group_by(&:rule_key).flat_map do |key, changes|
      stretches = changes.slice_when { |a, b| a.cause != b.cause }.select { |run| run.first.cause == :report }
      stretches = stretches.reverse if @reversed
      stretches.filter_map do |run|
        from, to = run.first.from, run.last.to
        from, to = to, from if @reversed
        [ run.last.fact, key, from, to ] unless from == to
      end
    end.group_by(&:first).transform_values { |rows| rows.map { |row| row.drop(1) } }
  end
end
