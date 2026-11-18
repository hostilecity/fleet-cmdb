# A change of one rule's result on one host (P2-S06, FR-2.2): from (nil for the first result) and to, when,
# and the rule version and snapshot that produced it, so the dashboard can show a failure appearing and clearing
# without a row per evaluation. An evaluation that changes nothing writes none. Pruned per NFR-2.
class CisResultChange < ApplicationRecord
  # Partitioned by time (ADR 0027): the table's key is (id, occurred_at), ids still come from one sequence.
  self.primary_key = :id

  belongs_to :host
  belongs_to :cis_rule
  belongs_to :cis_rule_version, optional: true
  # No foreign key (ADR 0027): the snapshot may no longer be kept, which readers treat like no snapshot.
  belongs_to :config_snapshot, optional: true

  scope :chronological, -> { order(:occurred_at, :id) }
end
