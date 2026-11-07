# A config report id already processed for a host, so a retried report is recognised (DEC-07). Pruned with the
# other history tables (NFR-2).
class ConfigReportReceipt < ApplicationRecord
  belongs_to :host
end
