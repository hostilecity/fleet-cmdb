# A package report id already processed for a host, so a retried report is recognised (DEC-07). Pruned with
# the other history tables (NFR-2).
class PackageReportReceipt < ApplicationRecord
  # Partitioned by time (ADR 0027): the table's key is (id, received_at), ids still come from one sequence.
  self.primary_key = :id

  belongs_to :host
end
