# The current result of one CIS-aligned rule on one host (P2-S06, FR-2.2): pass, fail, not_applicable,
# not_readable (with the reason), or not_evaluated (the rule is disabled, or the host has sent no config
# report). Names the rule version and config snapshot that produced it. Written only by CisEvaluation; every
# change of result is also a CisResultChange.
class CisResult < ApplicationRecord
  RESULTS = (CisRules::Evaluator::RESULTS + %w[not_evaluated]).freeze

  belongs_to :host
  belongs_to :cis_rule
  belongs_to :cis_rule_version, optional: true
  belongs_to :config_snapshot, optional: true

  validates :result, inclusion: { in: RESULTS }
end
