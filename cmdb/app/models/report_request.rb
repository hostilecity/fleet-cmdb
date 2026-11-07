# An operator's request for a fresh report of one type from a host's agent (P2-S03, FR-2.1, DEC-13). It is
# pending until a report of that type collected after it arrives (satisfied, with the report's id) or until
# expires_at passes (expired, with expired_at). Ended requests are kept, so the host page shows how each one
# ended; Retention prunes them after the retention window. ReportRequests is the only code that changes them.
class ReportRequest < ApplicationRecord
  # The report types, in the order the directive lists them: each is one agent report endpoint.
  TYPES = %w[config inventory packages].freeze
  STATES = %w[pending satisfied expired].freeze

  belongs_to :host
  belongs_to :requested_by, class_name: "Operator"

  validates :report_type, inclusion: { in: TYPES }
  validates :state, inclusion: { in: STATES }

  scope :pending, -> { where(state: "pending") }
  # Pending and not yet past its expiry: what the heartbeat directive carries. A pending request past its
  # expiry is waiting for ReportRequestExpiryJob to mark it expired, and is no longer sent.
  scope :outstanding, ->(now) { pending.where("report_requests.expires_at > ?", now) }

  # The state the host page shows: a pending request past its expiry already reads as expired.
  def display_state(now = Time.current) = state == "pending" && expires_at <= now ? "expired" : state
end
