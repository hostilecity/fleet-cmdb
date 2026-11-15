# What a heartbeat changes every time it arrives (FR-1.2, FR-1.4, #192): the server's time of the host's last
# heartbeat, its liveness status, and the agent's reported time. One row per host that has sent a heartbeat; none for a
# host awaiting first contact.
#
# A narrow table of its own, with no index but its primary key and half of each page kept free (fillfactor 50), so a
# heartbeat's update never changes an indexed column and stays heap-only (HOT): no index entry is written, and the
# old row version is reclaimed on its page without a vacuum. The wide hosts row, with its seven indexes, is not written
# by a steady heartbeat (ADR 0029). Only Liveness writes it, always holding the host row lock (AgentHostLock), so a
# reader holding that lock sees the latest committed row.
class HostLiveness < ApplicationRecord
  self.table_name = "host_liveness"
  self.primary_key = "host_id"

  belongs_to :host

  validates :liveness_status, inclusion: { in: Host::LIVENESS_STATUSES }
end
