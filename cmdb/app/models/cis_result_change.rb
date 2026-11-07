# A change of one rule's result on one host (P2-S06, FR-2.2): from (nil for the first result) and to, when,
# and the rule version and snapshot that produced it, so the dashboard can show a failure appearing and clearing
# without a row per evaluation. An evaluation that changes nothing writes none. Pruned per NFR-2.
class CisResultChange < ApplicationRecord
  belongs_to :host
  belongs_to :cis_rule
  belongs_to :cis_rule_version, optional: true
  belongs_to :config_snapshot, optional: true

  scope :chronological, -> { order(:occurred_at, :id) }
end
