# One rule's results on every host in the fleet (P2-D06, rule.html "Results on hosts" and "Fleet effect", and the
# disable confirmation). A host with no stored result yet shows as not evaluated, with why. Three queries whatever
# the fleet size: the hosts, their results for this rule with the versions, and which hosts have a config report.
class RuleResults
  ORDER = %w[fail not_readable pass not_applicable not_evaluated].freeze

  # result is the stored result, or "not_evaluated" when there is none; stored is the CisResult or nil.
  Row = Data.define(:host, :stored, :result, :reason)

  def initialize(rule)
    @rule = rule
  end

  def rows
    @rows ||= begin
      hosts = Host.in_fleet.to_a
      results = CisResult.where(cis_rule_id: @rule.id, host_id: hosts.map(&:id)).includes(:cis_rule_version).index_by(&:host_id)
      reporting = ConfigSnapshot.where(host_id: hosts.map(&:id)).distinct.pluck(:host_id).to_set
      hosts.map do |host|
        stored = results[host.id]
        reason = stored ? stored.reason : (reporting.include?(host.id) ? "The rule has not been evaluated on this host yet." : CisEvaluation::NO_REPORT)
        Row.new(host:, stored:, result: stored&.result || "not_evaluated", reason:)
      end.sort_by { |row| [ ORDER.index(row.result), row.host.name.downcase, row.host.id ] }
    end
  end

  def counts = @counts ||= rows.map(&:result).tally

  def count(result) = counts.fetch(result, 0)

  # Hosts with a real result: every host with a config report once the rule is enabled and evaluated.
  def evaluated = count("pass") + count("fail") + count("not_readable") + count("not_applicable")

  def without_report = rows.count { |row| row.reason == CisEvaluation::NO_REPORT }

  def failing = rows.select { |row| row.result == "fail" }.map(&:host)
end
