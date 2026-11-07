# A host's compliance summary (P2-S06, FR-2.2), from its current CIS results: how many rules passed, failed, did
# not apply, could not be read, and were not evaluated. A rule with no result for the host yet (created before
# its evaluation ran) counts as not evaluated, so the five always add up to the number of rules.
module CisCompliance
  Summary = Data.define(:passed, :failed, :not_applicable, :not_readable, :not_evaluated) do
    def total = passed + failed + not_applicable + not_readable + not_evaluated
  end

  COLUMNS = { "pass" => :passed, "fail" => :failed, "not_applicable" => :not_applicable, "not_readable" => :not_readable, "not_evaluated" => :not_evaluated }.freeze

  module_function

  def for_host(host_id) = for_hosts([ host_id ]).fetch(host_id)

  # { host_id => Summary } for each id, in two queries whatever the number of hosts.
  def for_hosts(host_ids)
    rules = CisRule.count
    counts = CisResult.where(host_id: host_ids).group(:host_id, :result).count
    host_ids.index_with do |host_id|
      values = COLUMNS.to_h { |result, name| [ name, counts.fetch([ host_id, result ], 0) ] }
      values[:not_evaluated] += rules - values.values.sum
      Summary.new(**values)
    end
  end
end
