class EvaluationRun
  # A rule change (CisRule.define!, enable!, disable!; one run for every rule a transaction changed): the rules on
  # every host in the fleet. CisEvaluation reads facts only on hosts where a rule applies.
  class CisRules
    def initialize(scope)
      @rule_ids = Array(scope["rule_ids"]).map(&:to_i)
    end

    attr_reader :rule_ids

    def hosts = Host.in_fleet

    # Nothing to prepare: rules are evaluated per host.
    def prepare_steps = []

    def prepare!(_checkpoint = nil) = nil

    # The hosts in the range whose shown compliance changed.
    def call(range) = CisEvaluation.evaluate!(hosts.where(id: range).pluck(:id), rule_ids:).changed_host_ids

    # A later run for these rules makes an older run for some of them redundant.
    def covers?(other) = other.is_a?(CisRules) && (other.rule_ids - rule_ids).empty?

    def refresh_always? = false
  end
end
