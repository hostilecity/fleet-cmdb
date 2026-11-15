# A Turbo stream with a change its open pages have not been told about yet, or LiveRefresh's marker that a flush
# is scheduled (#194). Written and read only by LiveRefresh; rows live for one refresh window.
class PendingRefresh < ApplicationRecord
  self.primary_key = "stream"
end
