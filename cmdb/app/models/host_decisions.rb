# One host's finding decisions as its Vulnerabilities tab shows them (VT-OVERRIDES #261, VT-D04, VT-D05): the latest
# decision of each advisory (active, or how it ended), whether the host still has an open finding of that advisory,
# and the decisions due. One query for the host, whatever its finding count; a host has few decisions.
#
# Decisions due, in advisories (VT-D05, epic decision 12): the Needs attention advisories with no decision in force
# (an accepted risk is not due), the decisions in force that end within EXPIRING_WITHIN days, the active ones past
# their last day (the hourly job has not ended them yet), and the suspended ones, while the host still has an open
# finding of their advisory.
class HostDecisions
  Entry = Data.define(:decision, :open)

  LATEST = <<~SQL.squish.freeze
    SELECT DISTINCT ON (d.advisory_id) d.*, EXISTS (
      SELECT 1 FROM vulnerability_findings f WHERE f.host_id = d.host_id AND f.advisory_id = d.advisory_id AND f.state <> 'resolved'
    ) AS has_open_finding
    FROM finding_decisions d WHERE d.host_id = ? ORDER BY d.advisory_id, d.id DESC
  SQL

  attr_reader :today

  def initialize(host_id, today: Date.current)
    @today = today
    decisions = FindingDecision.find_by_sql([ LATEST, host_id ])
    ActiveRecord::Associations::Preloader.new(records: decisions, associations: %i[created_by ended_by]).call
    @entries = decisions.to_h { |d| [ d.advisory_id, Entry.new(decision: d, open: d.has_open_finding) ] }
  end

  # The latest decision of an advisory on this host, or nil.
  def for(advisory_id) = @entries[advisory_id]&.decision

  # The decision in force for an advisory (active and not past its last day), or nil.
  def in_force(advisory_id) = self.for(advisory_id)&.then { |d| d if d.in_force?(today) }

  def accepted_ids = ids { |d| d.accepted? && d.in_force?(today) }
  def controlled_ids = ids { |d| d.control? && d.in_force?(today) }

  # Whether a decision in force ends soon (listed as due, VT-D05).
  def ending_soon?(decision) = decision.in_force?(today) && decision.expires_on <= today + FindingDecisions::EXPIRING_WITHIN

  # The advisory ids due a decision, given the host's Needs attention advisory ids.
  def due_ids(attention_ids)
    open = @entries.select { |_, entry| entry.open }.transform_values(&:decision)
    pending = open.select { |_, d| ending_soon?(d) || d.lapsed?(today) || d.suspended? }.keys
    ((attention_ids.to_set - accepted_ids - controlled_ids) | pending).to_a
  end

  private

  def ids = @entries.filter_map { |id, entry| id if yield(entry.decision) }.to_set
end
