# A host's compliance summary (P2-S06, FR-2.2), from its current CIS results: how many rules passed, failed, did
# not apply, could not be read, and were not evaluated. A rule with no result for the host yet (created before
# its evaluation ran) counts as not evaluated, so the five always add up to the number of rules.
module CisCompliance
  #
  # The pass rate (P2-D02, owner decision on the P2-D01 review, Q3) is passed / (passed + failed + not readable):
  # a check that could not be read counts against the host, because "we could not look" is not a pass. Not
  # applicable and not evaluated checks are left out. nil when no check counts.
  Summary = Data.define(:passed, :failed, :not_applicable, :not_readable, :not_evaluated) do
    def total = passed + failed + not_applicable + not_readable + not_evaluated
    def counted = passed + failed + not_readable
    def attention = failed + not_readable
    def pass_rate = counted.zero? ? nil : passed.fdiv(counted)
  end

  COLUMNS = { "pass" => :passed, "fail" => :failed, "not_applicable" => :not_applicable, "not_readable" => :not_readable, "not_evaluated" => :not_evaluated }.freeze

  module_function

  def for_host(host_id) = for_hosts([ host_id ]).fetch(host_id)

  # { host_id => Summary } for each id, in two queries whatever the number of hosts. Results are counted only
  # for the rules read first, so a rule created between the two queries is in neither (review of #110).
  def for_hosts(host_ids)
    rule_ids = CisRule.ids
    counts = CisResult.where(host_id: host_ids, cis_rule_id: rule_ids).group(:host_id, :result).count
    host_ids.index_with do |host_id|
      values = COLUMNS.to_h { |result, name| [ name, counts.fetch([ host_id, result ], 0) ] }
      values[:not_evaluated] += rule_ids.size - values.values.sum
      Summary.new(**values)
    end
  end
end
